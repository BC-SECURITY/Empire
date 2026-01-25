# Database Usage

Execute functions and hooks/filters are sent a SQLAlchemy database session. This does not need to be opened or closed, as the calling code handles that. The database session is passed in as a keyword argument.

```python
from sqlalchemy.orm import Session

def execute(self, command, **kwargs):
    user = kwargs.get('user', None)
    db: Session = kwargs.get('db', None)

    agents = self.main_menu.agentsv2.get_all(db)

    return "Execution complete"
```

It is important not to close the database session, as it will be used by the calling code and sent to other hooks/filters.

```python
from sqlalchemy.orm import Session
from empire.server.core.db import models

def on_agent_checkin(self, db: Session, agent: models.Agent):
    # Do something
    pass
```

When executing code outside of the execute function or hooks/filters, you will need to open a database session. This means that you must handle your database session in the plugin. Using the Context Manager syntax ensures the db session commits and closes properly.

```python
from empire.server.core.db.base import SessionLocal

def do_something():
    with SessionLocal.begin() as db:
        # Do the things with the db session
        pass
```

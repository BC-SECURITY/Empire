# multi\_generate\_agent

## Overview

`multi_generate_agent` is an Empire stager that generates a **stageless agent**, combining stage 0, stage 1, and stage 2 into a single file. Unlike traditional staged execution methods, this stager ensures that the agent is fully formed and ready to run immediately upon execution. This method is particularly useful for **debugging**, as it allows operators to analyze a fully assembled agent without concerns about staged delivery issues. It is also beneficial for **pre-staging agents**, making it useful in environments where fetching additional stages is undesirable or impractical. Additionally, it can help **reduce detection risk**, as all necessary code is included in a single artifact, which may be beneficial in environments with restricted outbound network connectivity.

## Compatibility

The `multi_generate_agent` stager is designed specifically for **Python, IronPython, and PowerShell agents**. It does not apply to **C# or Go agents**, as these are already compiled and inherently prestaged.

## How It Works

The `multi_generate_agent` stager generates a self-contained Empire agent file that incorporates all required stages. Upon execution, the agent **performs a full key exchange** with the Empire server but does **not execute the passed code immediately**, allowing operators to trigger execution when needed. This design makes it ideal for debugging or scenarios where an agent needs to be prestaged without requiring additional network requests to retrieve code.

![generate\_agent](../.gitbook/assets/multi_generate_agent.png)

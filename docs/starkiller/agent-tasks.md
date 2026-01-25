# Agent Tasks

Agent tasks in Empire are managed through a series of status updates that reflect the lifecycle of a task from creation to completion. These statuses help users understand the current state of tasks assigned to agents. Below are the possible statuses for agent taskings along with descriptions and representative icons.

## Queued

* **Description**: The task is queued for the agent. This status indicates that the task has been created and is waiting to be pulled by the agent.
* **Icon**:&#x20;

## Pulled

* **Description**: The agent has successfully pulled the tasking. This status signifies that the agent has received the task and is either processing it or about to start processing.
* **Icon**:&#x20;

## Completed

* **Description**: The task has returned data successfully. This indicates that the agent has finished executing the task and has returned the output.
* **Icon**:&#x20;

## Error

* **Description**: If an agent reports an error for a task, it will return an ERROR status. This status allows users to identify tasks that did not execute as expected.
* **Icon**: )

## Continuous

* **Description**: A special class for modules like keylogging since they are handled differently on the server due to their continuous nature. These tasks do not have a definite end and run continuously until stopped.
* **Icon**:&#x20;

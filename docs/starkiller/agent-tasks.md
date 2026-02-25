# Agent Tasks

Agent tasks in Empire are managed through a series of status updates that reflect the lifecycle of a task from creation to completion. These statuses help users understand the current state of tasks assigned to agents. Below are the possible statuses for agent taskings along with descriptions and representative icons.

## Queued

* **Description**: The task is queued for the agent. This status indicates that the task has been created and is waiting to be pulled by the agent.

<figure><img src="../.gitbook/assets/queued.svg" alt="" width="128"><figcaption></figcaption></figure>

## Pulled

* **Description**: The agent has successfully pulled the tasking. This status signifies that the agent has received the task and is either processing it or about to start processing.

<figure><img src="../.gitbook/assets/pulled.svg" alt="" width="128"><figcaption></figcaption></figure>

## Completed

* **Description**: The task has returned data successfully. This indicates that the agent has finished executing the task and has returned the output.

<figure><img src="../.gitbook/assets/completed.svg" alt="" width="128"><figcaption></figcaption></figure>

## Error

* **Description**: If an agent reports an error for a task, it will return an ERROR status. This status allows users to identify tasks that did not execute as expected.

<figure><img src="../.gitbook/assets/error.svg" alt="" width="128"><figcaption></figcaption></figure>

## Continuous

* **Description**: A special class for modules like keylogging, since they are handled differently on the server due to their continuous nature. These tasks do not have a definite end and run continuously until stopped.

<figure><img src="../.gitbook/assets/continious.svg" alt="" width="128"><figcaption></figcaption></figure>

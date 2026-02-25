# Autorun Modules

The **Autorun** feature allows users to predefine modules to automatically run when an agent becomes active.

{% embed url="https://www.youtube.com/embed/xTRhLt4DO5o?autoplay=1" %}

## Steps to Configure AutoRun

{% stepper %}
{% step %}
#### Navigate to Listeners

* From the sidebar, click on the "Listeners" icon.
* You will be taken to the Listeners list screen, where all the active listeners are shown.
{% endstep %}

{% step %}
#### Select a Listener

* Choose the listener you want to configure from the list. If no listener exists, create one by clicking on the "Create" button at the top right.
{% endstep %}

{% step %}
#### Access Autorun

* Once inside the listener’s details, you’ll notice an option for the **AutoRun Modules** as a tab.
* Click on this tab to configure what should happen automatically when the listener is engaged.
{% endstep %}

{% step %}
#### Choose Modules for AutoRun

* In the Autorun screen, you can select specific modules that will automatically run whenever an agent first connects.
{% endstep %}

{% step %}
#### Confirm Selection

* After selecting your desired modules, confirm your choices. Empire will automatically link these modules to the listener.
{% endstep %}

{% step %}
#### Running

* When the listener is activated, the selected modules will now automatically run on any new agent.
* You can view the tasks in real time from Starkiller.
{% endstep %}
{% endstepper %}

## Use Cases for AutoRun

* **Automation of Payloads:** Configure a listener to automatically deliver payloads to compromised machines without manual input.
* **Post-Exploitation Tasks:** Automatically run scripts to escalate privileges, gather system info, or set up persistence as soon as a listener engages.
* **Environment Monitoring:** Set up monitoring modules to run instantly when an agent calls back to the listener.

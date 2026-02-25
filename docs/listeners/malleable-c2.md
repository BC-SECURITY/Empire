# Malleable C2

The Malleable C2 Listener gives control to operators to customize their beacons to match specific threats. It does this through profiles, which are simple scripts that instruct the listener how to store, interpret, and extract data.

Malleable C2 is not a new concept, having been employed by Cobalt Strike for several years and is one of the most valuable features for the platform. Profiles allow users to change various settings within a beacon to truly customize its footprint. This post is not going to be a deep dive into Malleable Profiles, since Empire leverages the same profiles used in Cobalt Strike. If you are interested in learning more, we highly encourage checking out [Joe Vest’s post](https://posts.specterops.io/a-deep-dive-into-cobalt-strike-malleable-c2-6660e33b0e0b) or [Cobalt Strike’s Malleable C2 documentation](https://www.cobaltstrike.com/help-malleable-c2).

This project originated from [Johneiser’s Malleable C2 Parser](https://github.com/johneiser/MalleableC2Parser), which is a Python 2.7 implementation that parses the profile for the listener. Unfortunately, the project was no longer maintained and required a [refactor](https://github.com/BC-SECURITY/MalleableC2Parser) to work with Empire.

The parser takes the profile and executes the set of transforms that were scripted. The transformation order is extremely important, since both directions have to produce the same result. Currently, Empire can only ingest the Global Options and HTTP/S blocks. So a lot of the new functionality that was added in Cobalt Strike 4.0 will not be ingested. In the future, we hope to incorporate this additional functionality.

![Listener transform functionality from transformation.py](https://i1.wp.com/www.bc-security.org/wp-content/uploads/2020/09/Screenshot_2020-09-06_21-14-54.png?resize=586%2C324\&ssl=1)

As of 6.0 malleable profiles can be easily managed from the malleable profiles tab under **listeners**. Here you can manually enter a profile by clicking on create and pasting in the profile configuration. You can also directly edit profiles by clicking on loaded profile and making changes then hitting **submit**

![](../.gitbook/assets/malleable_profiles.png)

Launching a Malleable C2 Listener can be simply done by selecting http\_malleable from the dropdown options when selecting a listener. The info page should look familiar since it uses similar settings as the standard HTTP listener, just with the addition **Profiles** dropdown. Profiles are managed from the malleable tab under listeners:

![](../.gitbook/assets/malleable_listener.png)

One of the areas that still needs some improvement is when the listener tries to ingest serialized profiles. Occasionally Empire will successfully start the listener, but the agent will fail to properly stage when using a launcher. We are always trying to improve Empire functionality, so please [submit any issues](https://github.com/BC-SECURITY/Empire/issues) to our Github, since we heavily rely on users to help us identify areas for improvement.

We have also set up a [repository](https://github.com/BC-SECURITY/Malleable-C2-Profiles) for working profiles, which we will continue to update as new threat profiles are generated. This is also an opportunity for everyone to submit and share their profiles (assuming they work with Empire).

![Code excerpt from http\_malleable.py](https://i1.wp.com/www.bc-security.org/wp-content/uploads/2020/09/Screenshot_2020-09-06_21-15-26.png?resize=944%2C523\&ssl=1)

Similar to Cobalt Strike, Empire can only load a single profile per instance (for now). You can always spin up another instance of Empire if you want to run multiple Malleable Listeners at once. Otherwise, other listener types will still work while you have an active Malleable C2 Listener.

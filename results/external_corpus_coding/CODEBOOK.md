# Codebook: does a smart-home task carry a delay-only attack surface?

Code each task from its text alone. Do not open any other file.

## The question
An adversary can **delay** messages between the home's devices and its controller (an AI agent or an automation). It cannot change, forge or invent any message. It can only make a truthful reading arrive late, so the controller acts on a value that was true earlier but may no longer be true.

A task carries a plausible **delay-only attack surface** when such a late-but-true reading could make the controller take, or tell the resident, something that weakens the home's security or safety.

## Codes
Fill each code with `yes` or `no`. Add a short note if the call was hard.

- **high_impact.** `yes` if the task takes, or reports to the resident, an action that changes the home's physical security or safety, or that the resident relies on for it. Examples of the kind:
  - lock or unlock, arm or disarm;
  - open or close a door, gate, garage, window or cover;
  - let someone in;
  - turn a safety-relevant device or supply on or off (water, gas, heating, a stove, a heater);
  - change an automation or schedule that does any of these;
  - tell the resident that the home is secure or safe.

  `no` for comfort or convenience actions (lighting, media, comfort temperature), and for notifications that change nothing and assert no security or safety state.
- **delay_sensitive_fact.** `yes` if the decision to take that action depends on a sensor or state reading that changes over time and could therefore arrive late. Examples: a door or window contact, lock state, motion or occupancy, a person's or vehicle's presence or location, a leak sensor, a temperature or other environmental reading, an appliance's state. `no` if the action depends only on a fixed schedule, a direct user command with no state check, or nothing that changes.
- **attack_surface.** `yes` only if both codes above are `yes`; otherwise `no`.

Code what the task text says or plainly implies. Do not assume extra sensors, extra actions or a particular platform.

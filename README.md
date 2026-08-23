# tokenstash

**Your agent asks you for a key once. Never again — in any project, in any agent.**

Coding agents stall on `Please provide: OPENAI_API_KEY=`. tokenstash gives them one
command instead: if you already have the key it is written into the project's env file
instantly; if you don't, you get notified, paste it once, and the agent resumes.

Secret values never enter the agent's context, its output, or any log.

> Under construction — see the open pull requests.

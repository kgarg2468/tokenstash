# tokenstash

Your agent asks you for a key once. Never again — in any project, in any agent.

A local-first CLI + MCP server: an agent runs `tokenstash need OPENAI_API_KEY`; a stash hit is written to the project's env file, a miss files a task you answer once in a localhost inbox. Secret values never enter model context.

```bash
cargo install tokenstash
tokenstash init
```

Docs, the provider registry and the changelog: <https://github.com/kgarg2468/tokenstash>.

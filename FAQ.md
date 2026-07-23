# Rawframe FAQ

Rawframe is in early development. This page answers the questions people ask most often. Nothing here is a release promise, and details will change as the engine takes shape.

## What is Rawframe?

Rawframe is a performance-oriented, network-first engine and toolchain for 2D and 3D games and real-time simulations. The native core is written in C++23, and gameplay and tooling are written in a single language, Luau. Multiplayer is treated as a first-class concern from the first supported path, not as an add-on.

## What makes it different?

- **Network-first by design.** Servers are authoritative, the transport is QUIC, and prediction, replication, and trust boundaries are part of the architecture from the start rather than bolted on later.
- **One language.** Luau covers gameplay and tooling, so you are not switching languages between scripting, editor tools, and build steps. A trusted native C++ SDK exists for low-level extension when you need it.
- **2D and 3D in one engine.** The same world, schedule, and networking model serve both, under one set of rules.
- **Text-first, deterministic authoring.** Game data has a canonical, human-readable, diff-friendly text form, which keeps projects reviewable in version control and workable by both people and automated tooling.
- **Games, not avatars.** Rawframe is for building games and simulations, each its own product and world. It is not a shared-avatar UGC platform, and creators own what they make.

## What can it do today?

Rawframe is in its foundation phase. The architecture is specified and the first repository tooling is being built. There is no runnable engine yet and no release. If you are looking for something to download and use, that time has not arrived.

## Is it open source?

Rawframe is source-available under the Rawframe Source-Available License (RSAL). You can read, use, modify, and self-host the source. It is source-available, not open source in the OSI sense: building a competing engine or distribution platform with it is not permitted. External code contribution is closed for now while the foundation is built. See [LICENSE.md](LICENSE.md); the license text is authoritative.

## How will it make money, and what will it cost me?

Rawframe is free to use, modify, and self-host. There are three ways to ship a game, and the business model follows them:

1. **Publish on the Rawframe platform.** List your game so players can find and join it, with distribution handled for you.
2. **Self-host your own servers.** Run your own dedicated, server-authoritative game servers and sell access or slots. You keep control of the deployment.
3. **Export as a standalone product.** Ship your game as an independent product outside the platform. A standalone commercial product owes 5% of its lifetime gross revenue above USD 100,000. Below that threshold, nothing is owed.

The platform, hosting, and export tooling are planned, not finished. The royalty applies to standalone commercial exports and is defined precisely in the license and its export terms.

## What is the roadmap?

This is the intended path. It has no dates and will change.

1. **Foundation (now).** Architecture specification and the first repository tooling.
2. **First proof.** A headless, networked, server-authoritative world running Luau gameplay under measured performance budgets.
3. **Core engine.** World and entity systems, content, schema, replication, snapshots, and the dedicated server.
4. **Client and authoring.** Rendering, the editor, and the 2D and 3D content pipelines.
5. **Platform and release.** Listing, hosting, standalone export, and the first public availability.

Only the foundation phase is underway today.

## Who is behind it?

Rawframe is developed by INOVIXI.

## When can I use it, and how do I follow along?

There is no timeline yet. The best way to follow progress is to watch this repository and join the conversation in [GitHub Discussions](https://github.com/Rawframe-Project/rawframe/discussions).

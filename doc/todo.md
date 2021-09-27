# TODO

Curdleproofs works well but needs a few more tweaks before it can be truly used in production.

- When arkworks releases v0.4.0, curdleproofs should be refactored to inherit the various [ergonomic](https://github.com/arkworks-rs/algebra/commit/dd5b9d65ea3b419349a88cb84c571dda18b80aa5) [improvements](https://github.com/arkworks-rs/algebra/commit/fc7dc3e2a226eade8cda02f6eb2305bdd90b1da8).
- Be more consistent about projective/affine conversions (e.g. we are currently wasting cycles with single conversions to affine when using the transcript). This should be easier with [arkworks v0.4.0](https://github.com/arkworks-rs/algebra/commit/fc7dc3e2a226eade8cda02f6eb2305bdd90b1da8)
- Implement proof serialization/deserialization
- When blst releases a low-level API for lincomb and field/group operations, we will probably have to refactor this codebase to use blst, so that consensus clients can use it directly.


// A request target that `new URL(target, base)` cannot parse (e.g. `GET //`) is a 400, never a crash: the public
// handler parsed the path before its try, so the rejection was unhandled and Node exited (quality audit R1).
import assert from "node:assert/strict";
import { connect as netConnect } from "node:net";
import { after, before, describe, test } from "node:test";
import { makeWorld, type World } from "./support/world.ts";

/** Raw HTTP exchange: writes `head`, collects everything until the server closes the socket. */
function raw(port: number, head: string): Promise<string> {
  const socket = netConnect(port, "127.0.0.1");
  socket.write(head);
  return new Promise((resolve) => {
    let text = "";
    socket.on("data", (c: Buffer) => {
      text += c.toString("utf8");
    });
    socket.on("close", () => resolve(text));
    socket.on("error", () => undefined);
    setTimeout(() => socket.destroy(), 2000);
  });
}

describe("bridge: unparseable request targets", () => {
  let w: World;
  before(async () => {
    w = await makeWorld();
  });
  after(async () => {
    await w.close();
  });

  test("GET // answers 400 and the bridge keeps serving", async () => {
    const port = Number(new URL(w.publicUrl).port);
    const text = await raw(port, "GET // HTTP/1.1\r\nhost: 127.0.0.1\r\nconnection: close\r\n\r\n");
    assert.match(text, /^HTTP\/1\.1 400 /);
    assert.doesNotMatch(text, /at .*\.ts:\d+/, "no stack in the answer");
    const health = await fetch(`${w.publicUrl}/healthz`);
    assert.equal(health.status, 200);
  });

  test("a WebSocket upgrade on // is refused and the bridge keeps serving", async () => {
    const port = Number(new URL(w.publicUrl).port);
    const text = await raw(port, "GET // HTTP/1.1\r\nhost: 127.0.0.1\r\nconnection: Upgrade\r\nupgrade: websocket\r\nsec-websocket-version: 13\r\nsec-websocket-key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n");
    assert.match(text, /^HTTP\/1\.1 4\d\d /);
    const health = await fetch(`${w.publicUrl}/healthz`);
    assert.equal(health.status, 200);
  });
});

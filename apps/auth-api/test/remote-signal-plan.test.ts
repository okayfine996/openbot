import { describe, expect, it } from "vitest";
import { remoteSignalPlan } from "../src/server/remote-control-plane";

describe("remote Signal plan", () => {
  it("uses the optional Worker only for Team WebRTC tickets", () => {
    const plan = remoteSignalPlan({
      REMOTE_SIGNAL_URL: "wss://legacy.example.test/v1/signal",
      REMOTE_SIGNAL_WORKER_URL: "wss://worker.example.test/v1/signal",
      REMOTE_SIGNAL_INGRESS_WORKER_URL: "wss://ingress.example.test/v1/signal",
      REMOTE_SIGNAL_HOMES: "",
      REMOTE_SIGNAL_HOME_LOCATIONS: "",
    });
    expect(plan?.teamUrl).toBe("wss://worker.example.test/v1/signal");
    expect(plan?.entryUrl).toBe("wss://legacy.example.test/v1/signal");
    expect(plan?.ingressUrl).toBe("wss://ingress.example.test/v1/signal");
  });

  it("ignores an invalid Worker URL", () => {
    const plan = remoteSignalPlan({
      REMOTE_SIGNAL_URL: "wss://legacy.example.test/v1/signal",
      REMOTE_SIGNAL_WORKER_URL: "https://worker.example.test/v1/signal",
      REMOTE_SIGNAL_INGRESS_WORKER_URL: "https://ingress.example.test/v1/signal",
      REMOTE_SIGNAL_HOMES: "",
      REMOTE_SIGNAL_HOME_LOCATIONS: "",
    });
    expect(plan?.teamUrl).toBeNull();
  });
});

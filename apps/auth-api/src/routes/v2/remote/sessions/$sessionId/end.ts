import { createFileRoute } from "@tanstack/solid-router";
import { Effect } from "effect";
import { sha256 } from "../../../../../server/crypto";
import { runApiResponse } from "../../../../../server/effect-runtime";
import {
  apiError,
  bearerToken,
  remoteControlPlaneErrorResponse,
  requestRemoteControlPlane,
  requestUser,
} from "../../../../../server/request-auth";

export const Route = createFileRoute("/v2/remote/sessions/$sessionId/end")({
  server: {
    handlers: {
      POST: ({ request, params }) =>
        runApiResponse(
          Effect.gen(function* () {
            const user = yield* requestUser(request);
            if (!user) return apiError(401, "unauthorized", "Sign in is required.");
            const token = bearerToken(request);
            if (!token) return apiError(401, "unauthorized", "Sign in is required.");
            yield* requestRemoteControlPlane().endSession(user.id, params.sessionId, yield* sha256(token));
            return new Response(null, { status: 204 });
          }),
          remoteControlPlaneErrorResponse,
        ),
    },
  },
});

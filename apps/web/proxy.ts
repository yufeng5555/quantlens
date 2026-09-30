import { NextRequest, NextResponse } from "next/server";

import { isServableRequest } from "./local-preview-boundary";

export function proxy(request: NextRequest) {
  // Loopback always; one declared https deployment origin when an account
  // boundary is configured; nothing else. See local-preview-boundary.ts.
  if (isServableRequest(request.headers)) {
    return NextResponse.next();
  }

  return NextResponse.json(
    {
      detail: {
        code: "LOCAL_PREVIEW_BOUNDARY",
        message: "QuantLens local preview is available only from this device.",
      },
    },
    {
      status: 421,
      headers: {
        "Cache-Control": "private, no-store",
        Pragma: "no-cache",
      },
    },
  );
}

export const config = {
  matcher: "/:path*",
};

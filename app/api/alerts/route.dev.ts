import { NextResponse } from "next/server";
import { getThreatData } from "@/lib/threats";

export const dynamic = "force-dynamic";

/** Lightweight endpoint the live ticker polls every minute (the full payload is ~2 MB). */
export async function GET() {
  try {
    const { alerts, updatedAt } = await getThreatData();
    return NextResponse.json(
      { alerts, updatedAt },
      { headers: { "Cache-Control": "public, max-age=30" } },
    );
  } catch (e) {
    return NextResponse.json(
      { error: (e as Error).message ?? "Failed to load alerts" },
      { status: 502 },
    );
  }
}

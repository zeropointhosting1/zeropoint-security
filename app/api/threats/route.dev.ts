import { NextResponse } from "next/server";
import { getThreatData } from "@/lib/threats";

export const dynamic = "force-dynamic";

export async function GET() {
  try {
    const data = await getThreatData();
    return NextResponse.json(data, {
      headers: { "Cache-Control": "public, max-age=60, stale-while-revalidate=240" },
    });
  } catch (e) {
    return NextResponse.json(
      { error: (e as Error).message ?? "Failed to load threat feeds" },
      { status: 502 },
    );
  }
}

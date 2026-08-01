"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { Faster_One } from "next/font/google";

export default function History() {
  const [data, setData] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch("http://127.0.0.1:8000/api/history")
      .then((res) => res.json())
      .then((d) => {
        setData(d);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, []);

  const colorFor = (label: string) =>
    label === "Dangerous"
      ? "#F87171"
      : label === "Suspicious"
      ? "#FBBF24"
      : "#5EEAD4";

  return (
    <main className="min-h-screen bg-[#0B0F19] text-gray-200 px-6 py-14 sm:px-12">
      <div className="max-w-4xl mx-auto">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-extrabold text-white">Scan History</h1>
            <p className="text-sm text-gray-500 font-mono mt-1">
              Last {data.length} scans
            </p>
          </div>
          <Link
            href="/"
            className="text-sm font-mono text-cyan-400 hover:text-cyan-300"
          >
            ← New scan
          </Link>
        </div>

        {loading && (
          <p className="mt-8 text-gray-500 font-mono text-sm">Loading...</p>
        )}

        {!loading && data.length === 0 && (
          <p className="mt-8 text-gray-500 font-mono text-sm">
            No scans yet. Run one from the home page.
          </p>
        )}

        <div className="mt-8 space-y-3">
          {data.map((item: any, i: number) => {
            const color = colorFor(item.label);
            return (
              <div
                key={item.id ?? i}
                className="bg-[#121826] border border-white/10 rounded-xl p-5 flex items-center justify-between gap-4"
              >
                <p className="font-mono text-sm text-gray-300 truncate flex-1">
                  {item.url}
                </p>

                <div className="flex items-center gap-4 flex-shrink-0">
                  <span className="font-mono text-sm text-gray-500">
                    {item.risk_score}/100
                  </span>
                  <span
                    className="text-xs font-bold px-3 py-1 rounded-full"
                    style={{ backgroundColor: `${color}1A`, color }}
                  >
                    {item.label}
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </main>
  );
}


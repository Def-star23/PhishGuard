"use client";

import { useState } from "react";
import Link from "next/link";

export default function Home() {
  const [input, setInput] = useState("");
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);

  async function scan() {
    if (!input) return;

    setLoading(true);
    setResult(null);

    try {
      const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: input }),
      });

      const data = await res.json();
      setResult(data);
    } catch (error) {
      setResult({ error: "Backend not reachable" });
    }

    setLoading(false);
  }

  const score = result?.risk_score ?? 0;

  const labelColor =
    result?.label === "Dangerous"
      ? "#F87171"
      : result?.label === "Suspicious"
      ? "#FBBF24"
      : "#5EEAD4";

  const labelGlow =
    result?.label === "Dangerous"
      ? "shadow-[0_0_40px_-5px_rgba(248,113,113,0.5)]"
      : result?.label === "Suspicious"
      ? "shadow-[0_0_40px_-5px_rgba(251,191,36,0.5)]"
      : "shadow-[0_0_40px_-5px_rgba(94,234,212,0.5)]";

  // SVG circular gauge math
  const radius = 70;
  const circumference = 2 * Math.PI * radius;
  const dashOffset = circumference - (score / 100) * circumference;

  return (
    <main className="min-h-screen bg-[#0B0F19] text-gray-200 px-6 py-14 sm:px-12">
      <div className="max-w-4xl mx-auto">
        {/* Header */}
        <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <div className="relative">
            <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-cyan-400 to-blue-600 flex items-center justify-center text-2xl">
              🛡️
            </div>
          </div>
          <div>
            <h1 className="text-3xl sm:text-4xl font-extrabold tracking-tight text-white">
              PhishGuard
            </h1>
            <p className="text-sm text-gray-500 font-mono mt-0.5">
              AI-powered URL, email &amp; message threat detector
            </p>
          </div>
        </div>

        <Link
          href="/history"
          className="text-sm font-mono text-gray-400 hover:text-cyan-400 flex-shrink-0"
        >
          History →
        </Link>
        </div>

        {/* Input panel */}
        <div className="mt-10 bg-[#121826] border border-white/10 rounded-2xl p-6 sm:p-8">
          <label className="text-xs uppercase tracking-widest text-gray-500 font-mono">
            Input
          </label>

          <textarea
            className="w-full mt-3 p-4 rounded-xl bg-[#0B0F19] text-gray-100 text-base border border-white/10 focus:border-cyan-400/60 outline-none font-mono resize-none placeholder:text-gray-600"
            rows={4}
            placeholder="Paste your url/message/email..."
            value={input}
            onChange={(e) => setInput(e.target.value)}
          />

          <button
            onClick={scan}
            disabled={loading}
            className="mt-4 w-full sm:w-auto px-8 py-3.5 rounded-xl text-base font-bold bg-cyan-400 text-[#0B0F19] hover:bg-cyan-300 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            {loading ? "Scanning..." : "Scan"}
          </button>

          {loading && (
            <div className="mt-5 flex items-center gap-3 text-cyan-300 font-mono text-sm">
              <span className="relative flex h-2.5 w-2.5">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-cyan-400"></span>
              </span>
              Analyzing signals...
            </div>
          )}
        </div>

        {/* Results */}
        {result && !result.error && (
          <div className="mt-10 bg-[#121826] border border-white/10 rounded-2xl p-6 sm:p-8">
            {/* Score + label */}
            <div className="flex flex-col sm:flex-row items-center gap-8">
              <div className="relative w-44 h-44 flex-shrink-0">
                <svg className="w-44 h-44 -rotate-90" viewBox="0 0 170 170">
                  <circle
                    cx="85"
                    cy="85"
                    r={radius}
                    fill="none"
                    stroke="#1F2937"
                    strokeWidth="12"
                  />
                  <circle
                    cx="85"
                    cy="85"
                    r={radius}
                    fill="none"
                    stroke={labelColor}
                    strokeWidth="12"
                    strokeLinecap="round"
                    strokeDasharray={circumference}
                    strokeDashoffset={dashOffset}
                    style={{ transition: "stroke-dashoffset 0.8s ease" }}
                  />
                </svg>
                <div className="absolute inset-0 flex flex-col items-center justify-center">
                  <span className="text-4xl font-mono font-bold text-white">
                    {result.risk_score}
                  </span>
                  <span className="text-xs text-gray-500 font-mono">/ 100</span>
                </div>
              </div>

              <div className="text-center sm:text-left">
                <span
                  className={`inline-flex items-center gap-2 px-4 py-2 rounded-full font-bold text-sm ${labelGlow}`}
                  style={{ backgroundColor: `${labelColor}1A`, color: labelColor }}
                >
                  {result.label === "Dangerous"
                    ? "🔴"
                    : result.label === "Suspicious"
                    ? "🟡"
                    : "🟢"}
                  {result.label}
                </span>
                <p className="mt-4 text-gray-400 text-sm max-w-md leading-relaxed">
                  {result.ai_explanation?.explanation}
                </p>
              </div>
            </div>

            {/* Detection signal grid */}
            <h3 className="mt-10 text-xs uppercase tracking-widest text-gray-500 font-mono">
              Detection signals
            </h3>

            <div className="mt-4 grid grid-cols-2 sm:grid-cols-3 gap-3">
              <SignalChip
                label="Domain"
                value={result.analysis.url_analysis.domain ?? "N/A"}
                mono
              />
              <SignalChip
                label="HTTPS"
                value={result.analysis.url_analysis.https ? "Secure" : "Not secure"}
                alert={!result.analysis.url_analysis.https}
              />
              <SignalChip
                label="Suspicious TLD"
                value={result.analysis.url_analysis.suspicious_tld ? "Yes" : "No"}
                alert={result.analysis.url_analysis.suspicious_tld}
              />
              <SignalChip
                label="Brand impersonation"
                value={result.analysis.url_analysis.brand_impersonation ?? "None"}
                alert={!!result.analysis.url_analysis.brand_impersonation}
              />
              <SignalChip
                label="Typosquatting"
                value={result.analysis.url_analysis.uses_typosquatting ? "Detected" : "Not detected"}
                alert={result.analysis.url_analysis.uses_typosquatting}
              />
              <SignalChip
                label="IP address URL"
                value={result.analysis.url_analysis.ip_address ? "Yes" : "No"}
                alert={result.analysis.url_analysis.ip_address}
              />
            </div>

            {/* Language analysis */}
            <h3 className="mt-8 text-xs uppercase tracking-widest text-gray-500 font-mono">
              Language &amp; manipulation analysis
            </h3>

            <div className="mt-4 space-y-2">
              <FlagRow
                label="Urgency language"
                flags={result.analysis.keyword_analysis?.urgency_flags}
              />
              <FlagRow
                label="Credential requests"
                flags={result.analysis.keyword_analysis?.credential_request_flags}
              />
              <FlagRow
                label="Attachment language"
                flags={result.analysis.keyword_analysis?.attachment_flags}
              />
            </div>

            {/* Recommendations */}
            {result.ai_explanation?.recommendations && (
              <>
                <h3 className="mt-8 text-xs uppercase tracking-widest text-gray-500 font-mono">
                  Recommendations
                </h3>
                <ul className="mt-3 space-y-2">
                  {result.ai_explanation.recommendations.map(
                    (item: string, index: number) => (
                      <li
                        key={index}
                        className="flex gap-3 text-sm text-gray-300 leading-relaxed"
                      >
                        <span className="text-cyan-400 mt-0.5">→</span>
                        {item}
                      </li>
                    )
                  )}
                </ul>
              </>
            )}
          </div>
        )}

        {result?.error && (
          <p className="mt-10 text-red-400 font-mono text-sm">{result.error}</p>
        )}
      </div>
    </main>
  );
}

function SignalChip({
  label,
  value,
  alert,
  mono,
}: {
  label: string;
  value: string;
  alert?: boolean;
  mono?: boolean;
}) {
  return (
    <div className="bg-[#0B0F19] border border-white/5 rounded-xl p-3.5">
      <div className="text-[10px] uppercase tracking-wider text-gray-500">
        {label}
      </div>
      <div
        className={`mt-1 text-sm font-semibold truncate ${
          mono ? "font-mono" : ""
        } ${alert ? "text-red-400" : "text-gray-200"}`}
      >
        {alert ? "⚠ " : ""}
        {value}
      </div>
    </div>
  );
}

function FlagRow({ label, flags }: { label: string; flags?: string[] }) {
  const hasFlags = flags && flags.length > 0;
  return (
    <div className="flex items-start gap-3 bg-[#0B0F19] border border-white/5 rounded-xl p-3.5">
      <span className="text-xs uppercase tracking-wider text-gray-500 w-40 flex-shrink-0 mt-0.5">
        {label}
      </span>
      <span
        className={`text-sm ${hasFlags ? "text-amber-300" : "text-gray-500"}`}
      >
        {hasFlags ? flags!.join(", ") : "None detected"}
      </span>
    </div>
  );
}

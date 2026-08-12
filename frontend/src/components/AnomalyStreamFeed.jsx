import React from 'react';
import { AlertTriangle, Eye, ShieldAlert, Zap, Terminal } from 'lucide-react';

export default function AnomalyStreamFeed({ anomalyPackets, onInspectPacket, onInjectTest }) {
  if (!anomalyPackets || anomalyPackets.length === 0) {
    return (
      <div className="glass-panel p-12 text-center flex flex-col items-center justify-center min-h-[350px]">
        <div className="p-4 bg-rose-500/10 border border-rose-500/30 text-rose-400 rounded-2xl mb-4 glow-anomaly">
          <ShieldAlert className="w-10 h-10" />
        </div>
        <h3 className="text-lg font-bold text-white">No 0.1% Anomaly Packets Detected Yet</h3>
        <p className="text-sm text-slate-400 max-w-md mt-1 mb-6">
          The Isolation Forest model is continuously scanning incoming traffic against the 99.9 percentile threshold.
        </p>
        <button
          onClick={onInjectTest}
          className="flex items-center gap-2 px-5 py-2.5 bg-rose-600 hover:bg-rose-500 text-white font-semibold rounded-xl text-sm shadow-lg shadow-rose-600/30 transition-all"
        >
          <Zap className="w-4 h-4" /> Inject 0.1% Anomaly Test Packet
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-base font-bold text-white flex items-center gap-2">
          <span className="w-2.5 h-2.5 rounded-full bg-rose-500 animate-ping"></span>
          Top 0.1% Anomaly Packet Filter ({anomalyPackets.length})
        </h3>
        <span className="text-xs text-rose-400/80 font-mono">Filtered by 99.9 Percentile Cutoff Score</span>
      </div>

      <div className="space-y-3 max-h-[600px] overflow-y-auto pr-1">
        {anomalyPackets.map((pkt) => (
          <div
            key={pkt.id}
            className="glass-panel-anomaly p-4 transition-all hover:border-rose-400/60 group relative overflow-hidden"
          >
            {/* Background Glow Banner */}
            <div className="absolute top-0 right-0 w-32 h-32 bg-rose-500/5 rounded-full blur-2xl pointer-events-none"></div>

            <div className="flex flex-wrap items-start justify-between gap-4">
              {/* Header Info */}
              <div className="flex items-start gap-3">
                <div className="p-2 bg-rose-500/20 text-rose-400 border border-rose-500/40 rounded-lg mt-0.5">
                  <AlertTriangle className="w-5 h-5" />
                </div>
                <div>
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="px-2.5 py-0.5 bg-rose-500/20 text-rose-300 font-mono text-xs font-bold border border-rose-500/40 rounded">
                      SCORE: {pkt.score}
                    </span>
                    <span className="text-xs font-mono text-slate-400">
                      (Cutoff: {pkt.threshold})
                    </span>
                    <span className="text-xs text-slate-400 font-mono">
                      {pkt.time_str}
                    </span>
                    <span className="px-2 py-0.5 bg-slate-800 text-slate-300 text-xs font-mono rounded">
                      {pkt.protocol}
                    </span>
                  </div>

                  {/* IP Address Line */}
                  <div className="text-sm font-mono font-bold text-white mt-1.5 flex items-center gap-2">
                    <span className="text-rose-400">{pkt.src_ip}:{pkt.src_port}</span>
                    <span className="text-slate-500">➔</span>
                    <span className="text-cyan-300">{pkt.dst_ip}:{pkt.dst_port}</span>
                  </div>
                </div>
              </div>

              {/* Inspect Button */}
              <button
                onClick={() => onInspectPacket(pkt)}
                className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-rose-500/20 text-slate-300 hover:text-white border border-slate-700 hover:border-rose-500/50 rounded-lg text-xs font-medium transition-all"
              >
                <Eye className="w-4 h-4 text-cyan-400" /> Inspect Hex/Tree
              </button>
            </div>

            {/* AI Explanation Box */}
            <div className="mt-3 p-2.5 bg-slate-950/80 border border-slate-800/80 rounded-lg text-xs">
              <div className="flex items-center gap-1.5 text-rose-400 font-semibold mb-1">
                <Terminal className="w-3.5 h-3.5" /> AI Anomaly Explanation:
              </div>
              <p className="text-slate-300 font-mono leading-relaxed">
                {pkt.explanation || 'Isolation Forest Score Outlier'}
              </p>
            </div>

            {/* Quick Metrics Line */}
            <div className="mt-2.5 flex items-center gap-4 text-xs font-mono text-slate-400">
              <span>Length: <strong className="text-white">{pkt.length}B</strong></span>
              <span>Entropy: <strong className={pkt.entropy > 7.0 ? "text-rose-400" : "text-amber-400"}>{pkt.entropy}</strong> / 8.0</span>
              <span>Flags: <strong className="text-cyan-300">{pkt.tcp_flags}</strong></span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

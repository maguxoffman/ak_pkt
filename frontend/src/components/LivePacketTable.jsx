import React from 'react';
import { Eye, AlertOctagon } from 'lucide-react';

export default function LivePacketTable({ packets, onInspectPacket }) {
  return (
    <div className="glass-panel overflow-hidden">
      <div className="p-4 border-b border-slate-800 flex items-center justify-between">
        <h3 className="text-sm font-bold text-white flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse"></span>
          Live Stream Packet Inspector ({packets.length} recent)
        </h3>
        <span className="text-xs text-slate-400 font-mono">Real-time WebSocket Stream</span>
      </div>

      <div className="overflow-x-auto max-h-[550px] overflow-y-auto">
        <table className="w-full text-left text-xs">
          <thead className="bg-slate-900/90 text-slate-400 font-mono uppercase border-b border-slate-800 sticky top-0 z-10 backdrop-blur-md">
            <tr>
              <th className="px-4 py-3">Time</th>
              <th className="px-4 py-3">Score (IF)</th>
              <th className="px-4 py-3">Source</th>
              <th className="px-4 py-3">Destination</th>
              <th className="px-4 py-3">Proto</th>
              <th className="px-4 py-3">Len</th>
              <th className="px-4 py-3">Entropy</th>
              <th className="px-4 py-3">Flags</th>
              <th className="px-4 py-3 text-right">Inspect</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 font-mono">
            {packets.map((pkt) => {
              const isAnomaly = pkt.is_anomaly_01;
              return (
                <tr
                  key={pkt.id}
                  className={`transition-colors hover:bg-slate-800/50 ${
                    isAnomaly ? 'bg-rose-500/10 text-rose-200 border-l-4 border-l-rose-500' : 'text-slate-300'
                  }`}
                >
                  <td className="px-4 py-2.5 text-slate-400">{pkt.time_str}</td>
                  <td className="px-4 py-2.5">
                    <span
                      className={`px-2 py-0.5 rounded font-bold ${
                        isAnomaly 
                          ? 'bg-rose-500 text-white animate-pulse' 
                          : 'bg-slate-800 text-slate-300'
                      }`}
                    >
                      {pkt.score} {isAnomaly && '⚠️ 0.1%'}
                    </span>
                  </td>
                  <td className="px-4 py-2.5 text-rose-300 font-semibold">{pkt.src_ip}:{pkt.src_port}</td>
                  <td className="px-4 py-2.5 text-cyan-300">{pkt.dst_ip}:{pkt.dst_port}</td>
                  <td className="px-4 py-2.5">
                    <span className="px-1.5 py-0.5 bg-slate-800 border border-slate-700 rounded text-slate-300">
                      {pkt.protocol}
                    </span>
                  </td>
                  <td className="px-4 py-2.5">{pkt.length}B</td>
                  <td className={`px-4 py-2.5 ${pkt.entropy > 7.0 ? 'text-rose-400 font-bold' : 'text-slate-400'}`}>
                    {pkt.entropy}
                  </td>
                  <td className="px-4 py-2.5 text-slate-400">{pkt.tcp_flags}</td>
                  <td className="px-4 py-2.5 text-right">
                    <button
                      onClick={() => onInspectPacket(pkt)}
                      className="p-1.5 bg-slate-800 hover:bg-cyan-500/20 text-slate-400 hover:text-cyan-300 rounded transition-all"
                      title="Inspect Hex & Protocol Tree"
                    >
                      <Eye className="w-3.5 h-3.5" />
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

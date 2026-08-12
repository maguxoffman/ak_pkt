import React, { useState } from 'react';
import { X, ChevronDown, ChevronRight, Terminal, Cpu, FileCode, Layers } from 'lucide-react';

export default function WiresharkInspectorModal({ packet, onClose }) {
  const [openNodes, setOpenNodes] = useState({ 0: true, 1: true, 2: true, 3: true });

  if (!packet) return null;

  const toggleNode = (idx) => {
    setOpenNodes(prev => ({ ...prev, [idx]: !prev[idx] }));
  };

  // Convert full_hex or hex_payload into Wireshark 16-byte address rows
  const formatHexRows = (hexStr, asciiStr) => {
    if (!hexStr) return [];
    const tokens = hexStr.split(' ').filter(Boolean);
    const rows = [];
    for (let i = 0; i < tokens.length; i += 16) {
      const chunk = tokens.slice(i, i + 16);
      const addr = (i).toString(16).padStart(4, '0');
      const hexPart = chunk.join(' ');
      const asciiChunk = (asciiStr || '').slice(i, i + 16);
      rows.push({ addr, hexPart, asciiChunk });
    }
    return rows;
  };

  const hexRows = formatHexRows(packet.full_hex || packet.hex_payload, packet.ascii_payload);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-md">
      <div className="glass-panel w-full max-w-4xl max-h-[90vh] flex flex-col overflow-hidden shadow-2xl border-slate-700 animate-in fade-in zoom-in-95 duration-200">
        {/* Modal Header */}
        <div className="p-4 border-b border-slate-800 flex items-center justify-between bg-slate-900/90">
          <div className="flex items-center gap-3">
            <div className={`p-2 rounded-lg border ${
              packet.is_anomaly_01 
                ? 'bg-rose-500/20 text-rose-400 border-rose-500/40 glow-anomaly' 
                : 'bg-cyan-500/20 text-cyan-400 border-cyan-500/40'
            }`}>
              <FileCode className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-base font-bold text-white">Wireshark Packet Inspector #{packet.id}</h2>
                {packet.is_anomaly_01 && (
                  <span className="px-2 py-0.5 bg-rose-500/20 text-rose-400 border border-rose-500/40 text-xs font-mono font-bold rounded">
                    🚨 TOP 0.1% ANOMALY
                  </span>
                )}
              </div>
              <p className="text-xs text-slate-400 font-mono mt-0.5">
                {packet.time_str} | {packet.src_ip}:{packet.src_port} ➔ {packet.dst_ip}:{packet.dst_port} ({packet.protocol})
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-2 text-slate-400 hover:text-white bg-slate-800 hover:bg-slate-700 rounded-lg transition-all"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Scrollable Body */}
        <div className="p-5 overflow-y-auto space-y-5 text-xs font-mono">
          {/* AI Explanation Banner */}
          <div className={`p-4 rounded-xl border ${
            packet.is_anomaly_01
              ? 'bg-rose-950/40 border-rose-500/40 text-rose-200'
              : 'bg-slate-900 border-slate-800 text-slate-300'
          }`}>
            <div className="flex items-center justify-between mb-2">
              <span className="font-bold flex items-center gap-2 text-sm text-white">
                <Cpu className="w-4 h-4 text-cyan-400" /> Isolation Forest ML Analysis
              </span>
              <div className="flex gap-2">
                <span className="px-2.5 py-0.5 bg-slate-950 border border-slate-800 rounded text-slate-300">
                  Score: <strong className={packet.is_anomaly_01 ? "text-rose-400" : "text-emerald-400"}>{packet.score}</strong>
                </span>
                <span className="px-2.5 py-0.5 bg-slate-950 border border-slate-800 rounded text-slate-400">
                  Cutoff: {packet.threshold}
                </span>
              </div>
            </div>
            <p className="text-xs text-slate-300 bg-slate-950/80 p-2.5 rounded-lg border border-slate-800/80 leading-relaxed">
              <strong className="text-amber-400">Anomaly Diagnostic:</strong> {packet.explanation || 'Normal pattern'}
            </p>
          </div>

          {/* Section 1: Protocol Tree View */}
          <div>
            <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-2 flex items-center gap-2">
              <Layers className="w-4 h-4 text-cyan-400" /> Protocol Layer Tree
            </h3>
            <div className="bg-slate-950 border border-slate-800 rounded-xl p-3 space-y-2">
              {(packet.header_tree || []).map((node, idx) => (
                <div key={idx} className="border-b border-slate-900 last:border-0 pb-1.5">
                  <div
                    onClick={() => toggleNode(idx)}
                    className="flex items-center gap-2 cursor-pointer hover:text-cyan-300 text-slate-200 py-1 font-semibold"
                  >
                    {openNodes[idx] ? <ChevronDown className="w-4 h-4 text-cyan-400" /> : <ChevronRight className="w-4 h-4 text-slate-500" />}
                    <span>{node.layer}:</span>
                    <span className="text-slate-400 font-normal">{node.info}</span>
                  </div>
                  {openNodes[idx] && node.details && (
                    <div className="pl-6 space-y-0.5 text-slate-400 text-[11px] my-1 border-l border-slate-800 ml-2">
                      {node.details.map((d, dIdx) => (
                        <div key={dIdx} className="hover:text-slate-200 py-0.5">{d}</div>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>

          {/* Section 2: Wireshark Hex Dump & ASCII */}
          <div>
            <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-2 flex items-center gap-2">
              <Terminal className="w-4 h-4 text-rose-400" /> Raw Packet Payload Hexdump (16-Byte Boundaries)
            </h3>
            <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 font-mono text-xs overflow-x-auto">
              {hexRows.length > 0 ? (
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className="text-slate-500 border-b border-slate-900 pb-1">
                      <th className="w-16">Offset</th>
                      <th className="pr-4">Hex Bytes (16 Bytes / Line)</th>
                      <th>ASCII Printable</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-900/50">
                    {hexRows.map((row, rIdx) => (
                      <tr key={rIdx} className="hover:bg-slate-900/60">
                        <td className="text-cyan-400 font-bold py-1 select-none">{row.addr}</td>
                        <td className="text-slate-200 py-1 tracking-wider pr-4 font-mono">
                          {row.hexPart}
                        </td>
                        <td className="text-amber-300/90 py-1 font-mono">{row.asciiChunk}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : (
                <div className="text-slate-500 py-2">No raw payload bytes (Header Only Frame)</div>
              )}
            </div>
          </div>
        </div>

        {/* Modal Footer */}
        <div className="p-3 bg-slate-900/90 border-t border-slate-800 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg font-medium text-xs transition-all"
          >
            Close Inspector
          </button>
        </div>
      </div>
    </div>
  );
}

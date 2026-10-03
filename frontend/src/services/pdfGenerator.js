/**
 * ThreatXAI PDF Security Report Generator
 * Uses jsPDF and jspdf-autotable to generate vector PDF security analysis reports.
 */

import { jsPDF } from "jspdf";
import autoTable from "jspdf-autotable";

export function generateSecurityReport(resultData, options = {}) {
  const doc = new jsPDF({
    orientation: "portrait",
    unit: "mm",
    format: "a4",
  });

  const isMalicious = resultData.status === "MALICIOUS";
  const primaryColor = isMalicious ? [220, 38, 38] : [16, 185, 129]; // Red or Green
  const darkBg = [15, 23, 42]; // Slate 900
  const lightText = [248, 250, 252];
  const mutedText = [100, 116, 139];

  // Header Banner
  doc.setFillColor(...darkBg);
  doc.rect(0, 0, 210, 38, "F");

  // Title & Brand
  doc.setFont("helvetica", "bold");
  doc.setFontSize(20);
  doc.setTextColor(...primaryColor);
  doc.text("THREATXAI", 14, 16);

  doc.setFont("helvetica", "normal");
  doc.setFontSize(10);
  doc.setTextColor(...lightText);
  doc.text("Explainable AI Network Intrusion Detection Platform", 14, 23);
  doc.setFontSize(8);
  doc.setTextColor(...mutedText);
  doc.text("CIC-IDS2017 Trained LightGBM Multiclass Model • SHAP XAI Engine", 14, 30);

  // Report Metadata Box (Right aligned)
  doc.setFont("helvetica", "bold");
  doc.setFontSize(9);
  doc.setTextColor(...lightText);
  doc.text("SECURITY ASSESSMENT REPORT", 196, 14, { align: "right" });
  doc.setFont("helvetica", "normal");
  doc.setFontSize(8);
  doc.setTextColor(...mutedText);
  doc.text(`Generated: ${new Date().toLocaleString()}`, 196, 20, { align: "right" });
  doc.text(`Ref ID: TXA-${Math.random().toString(36).substring(2, 9).toUpperCase()}`, 196, 26, { align: "right" });
  doc.text(`Status: ${isMalicious ? "CRITICAL ALERT" : "VERIFIED NORMAL"}`, 196, 32, { align: "right" });

  let yPos = 46;

  // Executive Verdict Box
  doc.setFillColor(isMalicious ? 254 : 240, isMalicious ? 242 : 253, isMalicious ? 242 : 244);
  doc.setDrawColor(...primaryColor);
  doc.setLineWidth(0.8);
  doc.roundedRect(14, yPos, 182, 26, 3, 3, "FD");

  doc.setFont("helvetica", "bold");
  doc.setFontSize(14);
  doc.setTextColor(...primaryColor);
  const verdictTitle = isMalicious
    ? `THREAT DETECTED: ${resultData.prediction.toUpperCase()}`
    : "TRAFFIC STATUS: BENIGN (NORMAL)";
  doc.text(verdictTitle, 20, yPos + 10);

  doc.setFont("helvetica", "normal");
  doc.setFontSize(10);
  doc.setTextColor(30, 41, 59);
  const confText = `Model Confidence: ${(resultData.confidence * 100).toFixed(2)}% | Status: ${resultData.status} | Model: ${resultData.model_version || "lightgbm-cic-ids2017"}`;
  doc.text(confText, 20, yPos + 18);

  yPos += 34;

  // Section 1: Flow Metadata Table
  doc.setFont("helvetica", "bold");
  doc.setFontSize(11);
  doc.setTextColor(15, 23, 42);
  doc.text("1. Network Flow Telemetry & 5-Tuple", 14, yPos);
  yPos += 3;

  const flow = resultData.flow || resultData.metadata || {};
  const metaRows = [
    ["Source IP", flow.source_ip || "192.168.1.105", "Destination IP", flow.destination_ip || "Target Host"],
    ["Source Port", String(flow.source_port || 55000), "Destination Port", String(flow.destination_port || 80)],
    ["Protocol", flow.protocol || "TCP", "Flow Duration", flow.flow_duration_us ? `${flow.flow_duration_us.toLocaleString()} μs` : "Recorded"],
    ["Total Fwd Packets", String(flow.total_fwd_packets || "N/A"), "Total Bwd Packets", String(flow.total_bwd_packets || "N/A")],
  ];

  autoTable(doc, {
    startY: yPos,
    head: [["Attribute", "Value", "Attribute", "Value"]],
    body: metaRows,
    theme: "striped",
    headStyles: { fillColor: [30, 41, 59], textColor: [255, 255, 255], fontStyle: "bold", fontSize: 8 },
    bodyStyles: { fontSize: 8, textColor: [30, 41, 59] },
    margin: { left: 14, right: 14 },
  });

  yPos = doc.lastAutoTable.finalY + 10;

  // Section 2: Narrative Explanation Summary
  doc.setFont("helvetica", "bold");
  doc.setFontSize(11);
  doc.setTextColor(15, 23, 42);
  doc.text("2. Model Decision & Explainability Summary", 14, yPos);
  yPos += 5;

  doc.setFont("helvetica", "normal");
  doc.setFontSize(9);
  doc.setTextColor(51, 65, 85);
  const splitSummary = doc.splitTextToSize(
    resultData.summary || "No narrative summary generated for this flow.",
    182
  );
  doc.text(splitSummary, 14, yPos);
  yPos += splitSummary.length * 4.5 + 6;

  // Section 3: SHAP Feature Attributions Table
  doc.setFont("helvetica", "bold");
  doc.setFontSize(11);
  doc.setTextColor(15, 23, 42);
  doc.text("3. Key Contributing Network Features (SHAP Analysis)", 14, yPos);
  yPos += 3;

  const shapRows = (resultData.explanation || []).slice(0, 8).map((item, idx) => [
    `#${idx + 1}`,
    item.feature.trim(),
    Number(item.value).toFixed(2),
    Number(item.shap_value).toFixed(4),
    item.shap_value > 0 ? "+ Supporting" : "- Opposing",
  ]);

  autoTable(doc, {
    startY: yPos,
    head: [["Rank", "Feature Name", "Observed Value", "SHAP Value", "Impact on Verdict"]],
    body: shapRows.length ? shapRows : [["-", "No SHAP features available", "-", "-", "-"]],
    theme: "grid",
    headStyles: { fillColor: isMalicious ? [185, 28, 28] : [4, 120, 87], textColor: [255, 255, 255], fontSize: 8 },
    bodyStyles: { fontSize: 8 },
    margin: { left: 14, right: 14 },
  });

  yPos = doc.lastAutoTable.finalY + 10;

  // Section 4: Model Specifications
  if (yPos > 240) {
    doc.addPage();
    yPos = 20;
  }

  doc.setFont("helvetica", "bold");
  doc.setFontSize(11);
  doc.setTextColor(15, 23, 42);
  doc.text("4. AI Security Pipeline Specifications", 14, yPos);
  yPos += 5;

  doc.setFont("helvetica", "normal");
  doc.setFontSize(8.5);
  doc.setTextColor(71, 85, 105);
  const specs = [
    "• Model: LightGBM Gradient Boosted Decision Trees (15 multiclass output nodes)",
    "• Training Dataset: Canadian Institute for Cybersecurity CIC-IDS2017",
    "• Feature Extraction: Exact 78 statistical network traffic flow metrics with zero-division protection",
    "• Explainability Engine: SHAP TreeExplainer calculating exact Shapley attribution values per feature",
    "• Real-Time Monitoring: Kernel packet capture via Npcap/Scapy with bidirectional 5-tuple aggregation",
  ];
  specs.forEach((s) => {
    doc.text(s, 16, yPos);
    yPos += 4.5;
  });

  // Footer on all pages
  const pageCount = doc.internal.getNumberOfPages();
  for (let i = 1; i <= pageCount; i++) {
    doc.setPage(i);
    doc.setDrawColor(226, 232, 240);
    doc.line(14, 282, 196, 282);
    doc.setFont("helvetica", "normal");
    doc.setFontSize(7.5);
    doc.setTextColor(148, 163, 184);
    doc.text("ThreatXAI • Real-Time Explainable AI Intrusion Detection System", 14, 287);
    doc.text(`Page ${i} of ${pageCount}`, 196, 287, { align: "right" });
  }

  const filename = `ThreatXAI_Report_${resultData.prediction || "Flow"}_${Date.now()}.pdf`;
  doc.save(filename);
}

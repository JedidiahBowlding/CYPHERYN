from io import BytesIO
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    Image,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from .models import (
    AnalysisSnapshot,
    EvidenceSource,
    Finding,
    Investigation,
    NarrativeSnapshot,
    Target,
)

INK = colors.HexColor("#17212b")
TEAL = colors.HexColor("#147d72")
LIGHT = colors.HexColor("#edf5f4")
MUTED = colors.HexColor("#637381")


def build_pdf_report(
    investigation: Investigation,
    snapshot: AnalysisSnapshot,
    targets: list[Target],
    findings: list[Finding],
    sources: list[EvidenceSource],
    style: str,
    narrative: NarrativeSnapshot | None = None,
    brand_name: str = "SignalTrace",
    brand_accent: str = "#147d72",
    brand_logo: bytes | None = None,
) -> bytes:
    output = BytesIO()
    document = SimpleDocTemplate(
        output,
        pagesize=letter,
        rightMargin=0.65 * inch,
        leftMargin=0.65 * inch,
        topMargin=0.7 * inch,
        bottomMargin=0.65 * inch,
        title=snapshot.title,
        author="SignalTrace",
    )
    styles = getSampleStyleSheet()
    styles.add(
        ParagraphStyle(
            "ReportTitle",
            parent=styles["Title"],
            textColor=INK,
            fontSize=22,
            leading=27,
            spaceAfter=10,
        )
    )
    styles.add(
        ParagraphStyle(
            "Section",
            parent=styles["Heading2"],
            textColor=TEAL,
            fontSize=13,
            leading=17,
            spaceBefore=14,
            spaceAfter=8,
        )
    )
    styles.add(ParagraphStyle("Small", parent=styles["BodyText"], fontSize=8, textColor=MUTED))
    try:
        accent = colors.HexColor(brand_accent)
    except ValueError:
        accent = TEAL
    styles["Section"].textColor = accent
    story = []
    if brand_logo:
        try:
            logo = Image(BytesIO(brand_logo), width=0.55 * inch, height=0.55 * inch)
            logo.hAlign = "LEFT"
            story.extend([logo, Spacer(1, 5)])
        except Exception:  # noqa: S110 - invalid optional logos must not break reports
            pass
    story.extend(
        [
            Paragraph(f"{escape(brand_name.upper())} DEFENSIVE INTELLIGENCE", styles["Small"]),
            Paragraph(escape(snapshot.title), styles["ReportTitle"]),
            Paragraph(
                f"{style.title()} report | Generated {snapshot.created_at:%Y-%m-%d %H:%M UTC}",
                styles["Small"],
            ),
            Spacer(1, 14),
            _risk_banner(snapshot, styles, accent),
            Paragraph("Executive summary", styles["Section"]),
            Paragraph(escape(snapshot.executive_summary), styles["BodyText"]),
            Paragraph("Authorized scope", styles["Section"]),
            _scope_table(targets, styles),
            Paragraph("Prioritized recommendations", styles["Section"]),
        ]
    )
    if narrative is not None:
        story.extend(
            [
                Paragraph("Local AI narrative", styles["Section"]),
                Paragraph(escape(narrative.executive_summary), styles["BodyText"]),
                Paragraph(
                    f"AI_GENERATED_SUMMARY | Local model: {escape(narrative.model)} | "
                    "Grounded against persisted claim references",
                    styles["Small"],
                ),
            ]
        )
    if snapshot.recommendations:
        story.extend(_recommendation_blocks(snapshot, styles))
    else:
        story.append(
            Paragraph("No remediation actions are currently required.", styles["BodyText"])
        )
    story.extend([Paragraph("Evidence-supported claims", styles["Section"])])
    if snapshot.claims:
        story.extend(_claim_blocks(snapshot, styles))
    else:
        story.append(Paragraph("No active evidence-backed claims.", styles["BodyText"]))
    if snapshot.correlations:
        story.append(Paragraph("Cross-source correlations", styles["Section"]))
        for item in snapshot.correlations:
            story.append(
                KeepTogether(
                    [
                        Paragraph(escape(str(item["statement"])), styles["BodyText"]),
                        Paragraph(
                            f"{item['classification']} | Confidence {item['confidence']}% | "
                            f"Limitation: {item.get('limitation', 'None recorded')}",
                            styles["Small"],
                        ),
                        Spacer(1, 8),
                    ]
                )
            )
    story.extend(
        [
            Spacer(1, 16),
            Paragraph(
                "Classification note: observed facts are provider-backed records. Derived analysis "
                "is an inference and does not establish causation or compromise.",
                styles["Small"],
            ),
        ]
    )
    if style == "technical":
        story.extend(
            [
                PageBreak(),
                Paragraph("Technical evidence appendix", styles["Section"]),
                *(
                    [
                        Paragraph("Local AI technical summary", styles["Heading3"]),
                        Paragraph(escape(narrative.technical_summary), styles["BodyText"]),
                    ]
                    if narrative is not None
                    else []
                ),
                Paragraph("Active and historical findings", styles["Heading3"]),
                _finding_table(findings, styles),
                Paragraph("Evidence sources", styles["Heading3"]),
                _source_table(sources, styles),
            ]
        )
    document.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return output.getvalue()


def _risk_banner(snapshot: AnalysisSnapshot, styles, accent=TEAL) -> Table:
    score = Paragraph(
        f"<b>{snapshot.risk_score}/100</b><br/>{snapshot.risk_level.upper()}",
        styles["BodyText"],
    )
    metrics = snapshot.metrics or {}
    detail = Paragraph(
        f"{metrics.get('active_findings', 0)} active findings<br/>"
        f"{metrics.get('entities', 0)} entities | "
        f"{metrics.get('relationships', 0)} relationships<br/>"
        f"{metrics.get('unacknowledged_changes', 0)} unacknowledged changes",
        styles["BodyText"],
    )
    table = Table([[score, detail]], colWidths=[1.3 * inch, 5.6 * inch], rowHeights=[0.75 * inch])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), LIGHT),
                ("BOX", (0, 0), (-1, -1), 0.7, accent),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("ALIGN", (0, 0), (0, 0), "CENTER"),
                ("LEFTPADDING", (0, 0), (-1, -1), 12),
            ]
        )
    )
    return table


def _scope_table(targets: list[Target], styles) -> Table:
    rows = [["Type", "Canonical target", "Descendants"]]
    rows.extend(
        [
            target.target_type.value,
            target.canonical_value,
            "Yes" if target.include_descendants else "No",
        ]
        for target in targets
    )
    return _styled_table(rows, [1.2 * inch, 4.9 * inch, 0.8 * inch], styles)


def _finding_table(findings: list[Finding], styles) -> Table:
    rows = [["Severity", "Status", "Finding", "Asset", "Provider"]]
    rows.extend(
        [item.severity, item.status, item.title, item.asset_value, item.provider]
        for item in findings[:100]
    )
    return _styled_table(
        rows,
        [0.65 * inch, 0.7 * inch, 2.25 * inch, 2.15 * inch, 1.1 * inch],
        styles,
    )


def _source_table(sources: list[EvidenceSource], styles) -> Table:
    rows = [["Provider / version", "Query", "Retrieved", "SHA-256 fingerprint"]]
    rows.extend(
        [
            f"{item.provider} {item.provider_version} / {item.ruleset_version}",
            item.query,
            item.retrieved_at.strftime("%Y-%m-%d %H:%M"),
            (item.raw_response_hash or "Unavailable")[:16] + "...",
        ]
        for item in sources[:200]
    )
    return _styled_table(rows, [1.2 * inch, 2.4 * inch, 1.35 * inch, 1.9 * inch], styles)


def _styled_table(rows: list[list], widths: list[float], styles) -> Table:
    safe_rows = [[Paragraph(escape(str(value)), styles["Small"]) for value in row] for row in rows]
    table = Table(safe_rows, colWidths=widths, repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), INK),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#cbd5dc")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f7f9fa")]),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    return table


def _recommendation_blocks(snapshot: AnalysisSnapshot, styles) -> list:
    blocks = []
    for index, item in enumerate(snapshot.recommendations, 1):
        blocks.append(
            KeepTogether(
                [
                    Paragraph(
                        f"<b>{index}. [{escape(str(item['priority']).upper())}]</b> "
                        f"{escape(str(item['action']))}",
                        styles["BodyText"],
                    ),
                    Paragraph(f"Asset: {escape(str(item['asset']))}", styles["Small"]),
                    Spacer(1, 7),
                ]
            )
        )
    return blocks


def _claim_blocks(snapshot: AnalysisSnapshot, styles) -> list:
    blocks = []
    for item in snapshot.claims:
        blocks.append(
            KeepTogether(
                [
                    Paragraph(escape(str(item["statement"])), styles["BodyText"]),
                    Paragraph(
                        f"{item['classification']} | Confidence {item['confidence']}% | "
                        f"Evidence: {item.get('evidence', {})}",
                        styles["Small"],
                    ),
                    Spacer(1, 7),
                ]
            )
        )
    return blocks


def _footer(canvas, document) -> None:
    canvas.saveState()
    canvas.setStrokeColor(colors.HexColor("#d7e0e5"))
    canvas.line(0.65 * inch, 0.48 * inch, 7.85 * inch, 0.48 * inch)
    canvas.setFillColor(MUTED)
    canvas.setFont("Helvetica", 7)
    canvas.drawString(0.65 * inch, 0.3 * inch, "SignalTrace - Authorized defensive intelligence")
    canvas.drawRightString(7.85 * inch, 0.3 * inch, f"Page {document.page}")
    canvas.restoreState()

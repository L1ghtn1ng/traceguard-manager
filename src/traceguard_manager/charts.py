"""Geometry for the dashboard's server-rendered SVG chart."""

from dataclasses import dataclass

from .alerts import LEVELS, DashboardStats

CHART_WIDTH = 744
CHART_HEIGHT = 196
PLOT_TOP = 12
PLOT_HEIGHT = 150
SLOT_WIDTH = 31
BAR_WIDTH = 19


@dataclass(frozen=True, slots=True)
class ChartSegment:
    level: str
    y: float
    height: float


@dataclass(frozen=True, slots=True)
class ChartBar:
    x: int
    bucket: int
    label: str
    total: int
    show_label: bool
    segments: list[ChartSegment]


def build_timeline(stats: DashboardStats) -> list[ChartBar]:
    """Stack each hour's alerts by level, scaled so the busiest hour fills the plot."""
    peak = max(stats.timeline_peak, 1)
    baseline = PLOT_TOP + PLOT_HEIGHT
    bars: list[ChartBar] = []
    for index, hour in enumerate(stats.timeline):
        y = float(baseline)
        segments: list[ChartSegment] = []
        for level in reversed(LEVELS):  # least severe at the bottom
            count = hour.counts[level]
            if not count:
                continue
            height = max(round(count / peak * PLOT_HEIGHT, 1), 2.0)
            y -= height
            segments.append(ChartSegment(level=level, y=round(y, 1), height=height))
        bars.append(
            ChartBar(
                x=6 + index * SLOT_WIDTH,
                bucket=hour.bucket,
                label=hour.label,
                total=hour.total,
                show_label=index % 4 == 3,
                segments=segments,
            )
        )
    return bars


def share(count: int, peak: int) -> int:
    """Width of a horizontal bar as a whole percentage, never invisible for non-zero counts."""
    if count <= 0 or peak <= 0:
        return 0
    return max(round(count / peak * 100), 3)

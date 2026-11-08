"""Enclave - Hareketli arayüz parçaları: akan arka planlar ve açılış geçişi. Yalnızca animasyonlu stillerde çalışır."""

import math
import random
from typing import List, Optional

from PyQt6.QtCore import QEasingCurve, QPointF, QPropertyAnimation, QRectF, QTimer, Qt
from PyQt6.QtGui import QColor, QFont, QPainter, QPen
from PyQt6.QtWidgets import QFrame, QGraphicsOpacityEffect, QWidget

from .common import Theme

BACKDROPS = {"canli": "network", "siber": "matrix", "matrix": "matrix", "hud": "radar"}
GLYPHS = "01ABCDEF<>/{}#$%=+"

def backdrop_for(theme: Theme) -> Optional[str]:
    return BACKDROPS.get(theme.design.style) if theme.design.animated else None

class BackdropFrame(QFrame):
    """Yan panel. Animasyonlu stilde arkasında ağ düğümleri ya da akan kod sütunları çizer; içerik üstte kalır."""

    def __init__(self, theme: Theme, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setObjectName("Rail")
        self._kind = backdrop_for(theme)
        self._color = QColor(theme.design.dark.accent)
        self._rng = random.Random(11)
        self._nodes: List[list] = [
            [self._rng.random(), self._rng.random(), self._rng.uniform(-0.03, 0.03), self._rng.uniform(-0.03, 0.03)]
            for _ in range(30)
        ]
        self._columns: List[list] = []
        self._angle = 0.0
        self._font = QFont("Consolas", 10)
        self._timer = QTimer(self)
        self._timer.setInterval(40)
        self._timer.timeout.connect(self._tick)

    def showEvent(self, event) -> None:
        if self._kind:
            self._timer.start()
        super().showEvent(event)

    def hideEvent(self, event) -> None:
        self._timer.stop()
        super().hideEvent(event)

    def _tick(self) -> None:
        step = 0.04
        if self._kind == "network":
            for node in self._nodes:
                node[0] = (node[0] + node[2] * step * 4) % 1.0
                node[1] = (node[1] + node[3] * step * 4) % 1.0
        elif self._kind == "radar":
            self._angle = (self._angle + 2.6) % 360
        elif self._kind == "matrix":
            cols = max(1, self.width() // 22)
            while len(self._columns) < cols:
                self._columns.append([self._rng.random() * 1.4, self._rng.uniform(0.25, 0.6), self._rng.randrange(8, 16)])
            for column in self._columns:
                column[0] += column[1] * step
                if column[0] > 1.5:
                    column[0] = -self._rng.random() * 0.4
        self.update()

    def paintEvent(self, event) -> None:
        super().paintEvent(event)
        if not self._kind:
            return
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        if self._kind == "network":
            self._paint_network(painter)
        elif self._kind == "radar":
            self._paint_radar(painter)
        else:
            self._paint_matrix(painter)
        painter.end()

    def _paint_network(self, painter: QPainter) -> None:
        w, h = self.width(), self.height()
        points = [QPointF(n[0] * w, n[1] * h) for n in self._nodes]
        reach = max(w, h) * 0.2
        for i, a in enumerate(points):
            for b in points[i + 1:]:
                distance = math.hypot(a.x() - b.x(), a.y() - b.y())
                if distance < reach:
                    line = QColor(self._color)
                    line.setAlphaF(0.22 * (1 - distance / reach))
                    painter.setPen(QPen(line, 1))
                    painter.drawLine(a, b)
        painter.setPen(Qt.PenStyle.NoPen)
        for point in points:
            dot = QColor(self._color)
            dot.setAlphaF(0.34)
            painter.setBrush(dot)
            painter.drawEllipse(point, 2.2, 2.2)

    def _paint_radar(self, painter: QPainter) -> None:
        center = QPointF(self.width() / 2, self.height() * 0.42)
        reach = max(self.width(), self.height()) * 0.62
        line = QColor(self._color)
        line.setAlphaF(0.14)
        painter.setPen(QPen(line, 1))
        painter.setBrush(Qt.BrushStyle.NoBrush)
        for ring in range(1, 6):
            painter.drawEllipse(center, reach * ring / 5, reach * ring / 5)
        painter.drawLine(QPointF(0, center.y()), QPointF(self.width(), center.y()))
        painter.drawLine(QPointF(center.x(), 0), QPointF(center.x(), self.height()))
        for trail in range(24):
            radians = math.radians(self._angle - trail * 2)
            sweep = QColor(self._color)
            sweep.setAlphaF(0.3 * (1 - trail / 24))
            painter.setPen(QPen(sweep, 2))
            painter.drawLine(center, center + QPointF(math.cos(radians) * reach, math.sin(radians) * reach))

    def _paint_matrix(self, painter: QPainter) -> None:
        painter.setFont(self._font)
        h = self.height()
        for index, (head, _speed, length) in enumerate(self._columns):
            x = index * 22 + 6
            for tail in range(length):
                y = (head * h) - tail * 14
                if y < -14 or y > h:
                    continue
                glyph = GLYPHS[(index * 7 + tail * 3 + int(head * 9)) % len(GLYPHS)]
                color = QColor(self._color)
                color.setAlphaF(max(0.0, (0.5 if tail == 0 else 0.22) * (1 - tail / length)))
                painter.setPen(color)
                painter.drawText(QPointF(x, y), glyph)

def fade_in(widget: QWidget, duration: int = 520) -> None:
    """Parçayı saydamdan görünüre getirir. Bitince efekti kaldırır; böylece yazı çizimi bozulmaz."""
    effect = QGraphicsOpacityEffect(widget)
    effect.setOpacity(0.0)
    widget.setGraphicsEffect(effect)
    animation = QPropertyAnimation(effect, b"opacity", widget)
    animation.setDuration(duration)
    animation.setStartValue(0.0)
    animation.setEndValue(1.0)
    animation.setEasingCurve(QEasingCurve.Type.OutCubic)
    animation.finished.connect(lambda: widget.setGraphicsEffect(None))
    animation.start(QPropertyAnimation.DeletionPolicy.DeleteWhenStopped)

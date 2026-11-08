"""Enclave - Kasa bekçisi maskotlar.

Boştayken önce sabit durup kullanıcıyı bekler. Yanıt gelmezse cama tıklamaya başlar ve zaman geçtikçe hareketlenir. Kasa yalnızca parola yazılırken çıkar: maskot eğilip dinler,
kadranı çevirir, yazma durunca bırakır. Parolanın kendisi buraya hiç gelmez; yalnızca "tuşa basıldı" bilgisi gelir.
"""

import math
import random
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from PyQt6.QtCore import QElapsedTimer, QPointF, QRectF, QSize, QTimer, Qt
from PyQt6.QtGui import QColor, QFont, QLinearGradient, QPainter, QPainterPath, QPen, QRadialGradient, QTransform
from PyQt6.QtWidgets import QSizePolicy, QWidget

from .i18n import tr
from .common import Theme

CANVAS_W, CANVAS_H = 260.0, 200.0
GROUND = 176.0
CYCLE = 7.0
T_APPROACH = (2.6, 3.2)
T_TAPPING = (3.2, 5.0)
T_RETREAT = (5.0, 5.7)
TAPS_PER_SECOND = 2.5
TYPING_HOLD = 1.5
PATIENCE_WAIT = 10.0
PATIENCE_RAMP = 60.0
DIAL = QPointF(190, 134)

@dataclass(frozen=True)
class MascotInfo:
    key: str
    name: str
    summary: str

MASCOTS: Dict[str, MascotInfo] = {
    "kalkan": MascotInfo("kalkan", "Kalkan", "Kalkan gövdeli bekçi robot."),
    "ajan": MascotInfo("ajan", "Ajan", "Kapüşonlu, parlak gözlü siber ajan."),
    "tilki": MascotInfo("tilki", "Tilki", "Maskeli, kurnaz kasa ustası."),
    "bit": MascotInfo("bit", "Bit", "2D piksel robot."),
    "hayalet": MascotInfo("hayalet", "Hayalet", "2D piksel, sessiz izci."),
    "kilit": MascotInfo("kilit", "Kilitçi", "2D piksel, yürüyen asma kilit."),
}
DEFAULT_MASCOT = "kalkan"

PIXEL_UNIT = 7.0
SPRITES: Dict[str, Tuple[str, ...]] = {
    "bit": (
        ".......KK.......", ".......AA.......", "..KKKKKKKKKKKK..", ".KAAAAAAAAAAAAK.", ".KALLLLLLLLLLAK.",
        ".KAKKKKKKKKKKAK.", ".KAKEEKKKKEEKAK.", ".KAKEEKKKKEEKAK.", ".KAKKKKKKKKKKAK.", ".KAAAAAAAAAAAAK.",
        ".KAASSAAAASSAAK.", ".KAAAAAAAAAAAAK.", "..KKKKKKKKKKKK..", "...KSSK..KSSK...", "...KKKK..KKKK...",
    ),
    "hayalet": (
        ".....KKKKKK.....", "...KKAAAAAAKK...", "..KAAAAAAAAAAK..", ".KAALLAAAAAAAAK.", ".KALLAAAAAAAAAK.",
        ".KAAEEAAAAEEAAK.", ".KAAEEAAAAEEAAK.", ".KAAAAAAAAAAAAK.", ".KAAAASSSSAAAAK.", ".KAAAAAAAAAAAAK.",
        ".KAAAAAAAAAAAAK.", ".KAAAAAAAAAAAAK.", ".KAAAAAAAAAAAAK.", ".KAAKAAKKAAKAAK.", ".KKK.KK..KK.KKK.",
    ),
    "kilit": (
        ".....KKKKKK.....", "....KAAAAAAK....", "...KAAKKKKAAK...", "...KAK....KAK...", "...KAK....KAK...",
        "..KKKKKKKKKKKK..", ".KAAAAAAAAAAAAK.", ".KAAEEAAAAEEAAK.", ".KAAEEAAAAEEAAK.", ".KAAAAAKKAAAAAK.",
        ".KAAAAAKKAAAAAK.", ".KSSSSSSSSSSSSK.", "..KKKKKKKKKKKK..", "...KSK....KSK...", "...KKK....KKK...",
    ),
}

def _clamp(value: float) -> float:
    return max(0.0, min(1.0, value))

def _span(t: float, window: Tuple[float, float]) -> float:
    return _clamp((t - window[0]) / (window[1] - window[0]))

def _ease(x: float) -> float:
    return x * x * (3 - 2 * x)

def _mix(a: QColor, b: QColor, amount: float) -> QColor:
    return QColor(
        int(a.red() + (b.red() - a.red()) * amount),
        int(a.green() + (b.green() - a.green()) * amount),
        int(a.blue() + (b.blue() - a.blue()) * amount),
    )

class CyberMascot(QWidget):
    def __init__(self, theme: Theme, size: int = 260, on_dark: bool = True, kind: str = DEFAULT_MASCOT,
                 parent: Optional[QWidget] = None, demo: bool = False):
        super().__init__(parent)
        self.setObjectName("Mascot")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Preferred)
        self.setMinimumSize(130, 100)
        self._hint = size
        self._on_dark = on_dark
        self.set_theme(theme)
        self.set_kind(kind)

        self._clock = QElapsedTimer()
        self._clock.start()
        self._demo = demo
        self._active_at = 0.0
        self._insist_until = -1.0
        self._phase = 0.0
        self._live = 1.0
        self._manual_energy = 1.0
        self._manual: Optional[float] = None
        self._mood = ""
        self._mood_until = 0.0
        self._typing_until = -1.0
        self._engage = 0.0
        self._last_frame = 0.0
        self._dial = 0.0
        self._dial_target = 0.0
        self._rng = random.Random(7)
        self._clicks: List[Tuple[float, float]] = []
        self._timer = QTimer(self)
        self._timer.setInterval(33)
        self._timer.timeout.connect(self.update)

    def set_theme(self, theme: Theme) -> None:
        design = theme.design
        pal = design.dark if self._on_dark else theme.palette
        self._accent = QColor(pal.accent)
        self._shade = self._accent.darker(150)
        self._light = self._accent.lighter(135)
        self._ink = QColor(design.dark.rail).darker(125)
        self._eye = QColor("#F4F3FC")
        self._metal = _mix(QColor(design.dark.surface_alt), self._accent, 0.22)
        self._metal_dark = self._metal.darker(140)
        self._good = QColor(design.dark.success)
        self._warn = QColor(design.dark.warning)
        self._bad = QColor(design.dark.danger)
        self.update()

    def set_kind(self, kind: str) -> None:
        self.kind = kind if kind in MASCOTS else DEFAULT_MASCOT
        info = MASCOTS[self.kind]
        self.setAccessibleName(tr("Enclave maskotu {}", tr(info.name)))
        self.setToolTip(tr("{}: kasanızın bekçisi. Tıklayınca cama vurur.", tr(info.name)))
        self.update()

    def sizeHint(self) -> QSize:
        return QSize(self._hint, int(self._hint * CANVAS_H / CANVAS_W))

    def set_time(self, seconds: float, engage: Optional[float] = None, energy: float = 1.0) -> None:
        """Test ve kare kare çıktı için zamanı, eğilme düzeyini ve hareketliliği sabitler; energy < 0 bekleme demektir."""
        self._manual = seconds
        self._manual_energy = energy
        self._phase = seconds
        if engage is not None:
            self._engage = engage
        self.update()

    def nudge(self) -> None:
        """Kullanıcı bir şey yaptı: maskot sakinleşir ve yeniden beklemeye başlar."""
        now = self._now()
        if now >= self._insist_until:
            self._active_at = now

    def pick_lock(self) -> None:
        """Parola alanına her yazıldığında çağrılır; kadran çevrilir, yazma durunca maskot bırakır."""
        self.nudge()
        self._typing_until = self._now() + TYPING_HOLD
        self._dial_target += self._rng.choice((-1, 1)) * self._rng.uniform(35, 110)
        self._clicks.append((self._now(), self._rng.uniform(-14, 14)))
        self._clicks = self._clicks[-5:]

    def stop_picking(self) -> None:
        self._typing_until = -1.0

    @property
    def picking(self) -> bool:
        return self._now() < self._typing_until

    def alert(self) -> None:
        self.stop_picking()
        self._set_mood("alert", 1.8)

    def celebrate(self) -> None:
        self.stop_picking()
        self._set_mood("happy", 2.2)

    def _set_mood(self, mood: str, seconds: float) -> None:
        self._mood = mood
        self._mood_until = self._now() + seconds

    def _now(self) -> float:
        return self._manual if self._manual is not None else self._clock.elapsed() / 1000.0

    def mousePressEvent(self, event) -> None:
        now = self._now()
        self._insist_until = now + 4
        self._active_at = now - PATIENCE_WAIT - PATIENCE_RAMP * 0.5
        self._phase = T_APPROACH[0]
        super().mousePressEvent(event)

    def _energy(self, now: float) -> float:
        """-1 bekliyor, 0 ilk çekingen tıklama, 1 tam hareketli."""
        if self._manual is not None:
            return self._manual_energy
        if self._demo:
            return 1.0
        idle = now - self._active_at
        return -1.0 if idle < PATIENCE_WAIT else _clamp((idle - PATIENCE_WAIT) / PATIENCE_RAMP)

    def showEvent(self, event) -> None:
        if self._manual is None:
            self._timer.start()
        super().showEvent(event)

    def hideEvent(self, event) -> None:
        self._timer.stop()
        self.stop_picking()
        super().hideEvent(event)

    def paintEvent(self, _event) -> None:
        now = self._now()
        dt = min(0.1, max(0.0, now - self._last_frame))
        self._last_frame = now
        if self._manual is None:
            target = 1.0 if self.picking else 0.0
            step = dt / (0.3 if target else 0.55)
            self._engage = min(target, self._engage + step) if self._engage < target else max(target, self._engage - step)
            self._dial += (self._dial_target - self._dial) * _clamp(dt * 9)
        engage = _ease(self._engage)
        calm = 1 - engage
        energy = self._energy(now)
        waiting = energy < 0 or engage > 0.5
        energy = max(0.0, energy)
        self._live = max(energy, engage)
        if self._manual is None:
            self._phase = T_APPROACH[0] - 0.3 if waiting else self._phase + dt * (0.45 + 0.55 * energy)
        t = self._phase % CYCLE
        mood = self._mood if now < self._mood_until else ""
        happy = mood == "happy"
        pixel = self.kind in SPRITES

        reach = 0.0 if waiting else _ease(_span(t, T_APPROACH)) * (1 - _ease(_span(t, T_RETREAT))) * calm
        near = reach * (0.45 + 0.55 * energy)
        beat = ((t - T_TAPPING[0]) * TAPS_PER_SECOND) % 1.0
        tapping = T_TAPPING[0] <= t < T_TAPPING[1] and reach > 0.9
        impact = max(0.0, 1 - beat * 5) if tapping else 0.0
        sway = math.sin(now * 1.2) * 34 * energy * (1 - reach) * calm
        presence = engage
        lean = engage

        scale = min(self.width() / CANVAS_W, self.height() / CANVAS_H)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.translate((self.width() - CANVAS_W * scale) / 2, (self.height() - CANVAS_H * scale) / 2)
        painter.scale(scale, scale)

        moving = self._live > 0.2
        bob = (-3.0 * (int(now * 4) % 2) if moving else 0.0) if pixel else math.sin(now * 2.2) * 1.5 * (1 - lean * 0.7) * self._live
        shake = math.sin(now * 40) * 1.8 if mood == "alert" else 0.0
        size = 1 + 0.27 * near + 0.04 * impact
        anchor = QPointF(130 + sway - 42 * presence + shake, GROUND + 16 * near)
        pose = QTransform()
        pose.translate(anchor.x() + (8 * lean if pixel else 0), anchor.y() + bob)
        pose.scale(size, size)
        if not pixel:
            pose.rotate(13 * lean)

        self._shadow(painter, anchor.x(), 60 * size)
        if presence > 0.01:
            self._shadow(painter, 190 + (1 - presence) * 70, 74)

        heading = math.cos(now * 1.2) * 2.6 * energy * (1 - reach) * calm
        look = (presence * 3.0 + heading, 0.8 * lean)
        painter.save()
        painter.setTransform(pose, True)
        if pixel:
            self._sprite(painter, now, mood, happy, lean * 0.45)
        else:
            draw = {"ajan": self._agent, "tilki": self._fox}.get(self.kind, self._robot)
            self._feet(painter, now)
            draw(painter, now, mood, engage > 0.2)
            self._eyes(painter, now, mood, happy, look, lean * 0.45)
        painter.restore()

        if presence > 0.01:
            self._safe(painter, now, presence, self._dial, mood, engage)
        glass = QPointF(anchor.x() + 26 * size, 92)
        hand = glass + QPointF(0, 12 * (1 - impact) * (1 - impact)) if reach > 0.5 else None
        self._arms(painter, pose, now, presence, engage, mood, happy, hand)
        if presence > 0.6 and lean > 0.05:
            self._stethoscope(painter, pose, now, lean)
        if tapping:
            self._glass_tap(painter, glass, beat)
        if engage > 0.05:
            self._click_marks(painter, now)
        painter.end()

    def _sprite(self, p: QPainter, now: float, mood: str, happy: bool, squint: float) -> None:
        rows = list(SPRITES[self.kind])
        if self._live > 0.2 and int(now * 4) % 2:
            rows[-2:] = [row[::-1] for row in rows[-2:]]
        blink = (now % 4.3) < 0.14 or squint > 0.3
        eye = self._bad if mood == "alert" else self._eye
        colors = {"A": self._accent, "S": self._shade, "L": self._light, "K": self._ink, "W": self._eye, "E": eye}
        eye_rows = [index for index, row in enumerate(rows) if "E" in row]
        unit = PIXEL_UNIT
        left, top = -8 * unit, -len(rows) * unit
        p.setRenderHint(QPainter.RenderHint.Antialiasing, False)
        p.setPen(Qt.PenStyle.NoPen)
        for y, row in enumerate(rows):
            for x, cell in enumerate(row):
                if cell == ".":
                    continue
                color = colors[cell]
                if cell == "E" and (blink or happy) and y == eye_rows[-1 if happy else 0]:
                    color = self._ink if "K" in row[5:11] and self.kind == "bit" else self._accent
                p.fillRect(QRectF(left + x * unit, top + y * unit, unit + 0.4, unit + 0.4), color)
        p.setRenderHint(QPainter.RenderHint.Antialiasing, True)

    @staticmethod
    def _shadow(p: QPainter, x: float, width: float) -> None:
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor(0, 0, 0, 70))
        p.drawEllipse(QRectF(x - width / 2, GROUND - 2, width, 8))

    def _feet(self, p: QPainter, now: float) -> None:
        p.setPen(QPen(self._ink, 2.4))
        p.setBrush(self._shade)
        step = math.sin(now * 2.2) * 0.8 * self._live
        p.drawRoundedRect(QRectF(-21, -10 + step, 17, 10), 4, 4)
        p.drawRoundedRect(QRectF(4, -10 - step, 17, 10), 4, 4)

    def _body_brush(self, top: float, bottom: float) -> QLinearGradient:
        gradient = QLinearGradient(-44, top, 44, bottom)
        gradient.setColorAt(0, self._light)
        gradient.setColorAt(0.45, self._accent)
        gradient.setColorAt(1, self._shade)
        return gradient

    def _robot(self, p: QPainter, now: float, mood: str, focused: bool) -> None:
        p.setPen(QPen(self._shade, 3, cap=Qt.PenCapStyle.RoundCap))
        p.drawLine(QPointF(0, -128), QPointF(0, -142))
        glow = (math.sin(now * (7 if focused else 2.6)) + 1) / 2
        color = self._bad if mood == "alert" else self._accent
        if mood == "alert":
            glow = 1.0 if int(now * 8) % 2 == 0 else 0.25
        halo = QRadialGradient(QPointF(0, -146), 13)
        tint = QColor(color)
        tint.setAlphaF(0.55 * glow)
        halo.setColorAt(0, tint)
        halo.setColorAt(1, QColor(0, 0, 0, 0))
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(halo)
        p.drawEllipse(QPointF(0, -146), 13, 13)
        p.setBrush(_mix(self._shade, self._light, glow))
        p.drawEllipse(QPointF(0, -146), 4.6, 4.6)

        shield = QPainterPath()
        shield.moveTo(-44, -116)
        shield.quadTo(-44, -128, -32, -128)
        shield.lineTo(32, -128)
        shield.quadTo(44, -128, 44, -116)
        shield.lineTo(44, -62)
        shield.quadTo(44, -28, 0, -6)
        shield.quadTo(-44, -28, -44, -62)
        shield.closeSubpath()
        p.setPen(QPen(self._ink, 3.2, join=Qt.PenJoinStyle.RoundJoin))
        p.setBrush(self._body_brush(-128, -6))
        p.drawPath(shield)
        self._visor(p, QRectF(-34, -110, 68, 30), 13)
        self._chest_lock(p, QPointF(0, -52), mood)

    def _visor(self, p: QPainter, rect: QRectF, radius: float) -> None:
        p.setPen(QPen(self._ink.darker(130), 2))
        p.setBrush(self._ink)
        p.drawRoundedRect(rect, radius, radius)

    def _chest_lock(self, p: QPainter, c: QPointF, mood: str) -> None:
        p.setPen(QPen(self._ink, 3.6, cap=Qt.PenCapStyle.RoundCap))
        p.setBrush(Qt.BrushStyle.NoBrush)
        shackle = QPainterPath(QPointF(c.x() - 7, c.y() - 3))
        shackle.lineTo(c.x() - 7, c.y() - 9)
        shackle.quadTo(c.x() - 7, c.y() - 15, c.x(), c.y() - 15)
        shackle.quadTo(c.x() + 7, c.y() - 15, c.x() + 7, c.y() - 9)
        shackle.lineTo(c.x() + 7, c.y() - 3)
        p.drawPath(shackle)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(self._ink)
        p.drawRoundedRect(QRectF(c.x() - 11, c.y() - 4, 22, 18), 4, 4)
        p.setBrush(self._bad if mood == "alert" else self._light)
        p.drawEllipse(QPointF(c.x(), c.y() + 4), 3, 3)

    def _agent(self, p: QPainter, now: float, mood: str, focused: bool) -> None:
        hood = QPainterPath(QPointF(-46, -6))
        hood.quadTo(-52, -70, -38, -106)
        hood.quadTo(-24, -142, 0, -142)
        hood.quadTo(24, -142, 38, -106)
        hood.quadTo(52, -70, 46, -6)
        hood.closeSubpath()
        p.setPen(QPen(self._ink, 3.2, join=Qt.PenJoinStyle.RoundJoin))
        p.setBrush(self._body_brush(-142, -6))
        p.drawPath(hood)
        self._visor(p, QRectF(-30, -116, 60, 46), 22)
        p.setPen(QPen(self._ink, 2.4, cap=Qt.PenCapStyle.RoundCap))
        p.drawLine(QPointF(-12, -68), QPointF(-15, -44))
        p.drawLine(QPointF(12, -68), QPointF(15, -44))
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(self._ink)
        p.drawEllipse(QPointF(-15, -42), 2.6, 2.6)
        p.drawEllipse(QPointF(15, -42), 2.6, 2.6)
        p.setBrush(QColor(self._ink.red(), self._ink.green(), self._ink.blue(), 120))
        p.drawRoundedRect(QRectF(-24, -30, 48, 15), 6, 6)

    def _fox(self, p: QPainter, now: float, mood: str, focused: bool) -> None:
        tail = QPainterPath(QPointF(-34, -22))
        wag = math.sin(now * 3) * 5
        tail.quadTo(-78, -30 + wag, -68, -74 + wag)
        tail.quadTo(-50, -52, -28, -42)
        tail.closeSubpath()
        p.setPen(QPen(self._ink, 3, join=Qt.PenJoinStyle.RoundJoin))
        p.setBrush(self._shade)
        p.drawPath(tail)
        p.setBrush(self._body_brush(-70, -6))
        p.drawRoundedRect(QRectF(-34, -72, 68, 66), 26, 26)
        p.setBrush(self._body_brush(-136, -62))
        for sign in (-1, 1):
            ear = QPainterPath(QPointF(sign * 42, -102))
            ear.lineTo(sign * 42, -140)
            ear.lineTo(sign * 12, -116)
            ear.closeSubpath()
            p.drawPath(ear)
        head = QPainterPath(QPointF(-46, -104))
        head.quadTo(-44, -124, 0, -124)
        head.quadTo(44, -124, 46, -104)
        head.quadTo(40, -78, 0, -58)
        head.quadTo(-40, -78, -46, -104)
        p.drawPath(head)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(self._eye)
        cheek = QPainterPath(QPointF(-24, -84))
        cheek.quadTo(0, -92, 24, -84)
        cheek.quadTo(14, -68, 0, -60)
        cheek.quadTo(-14, -68, -24, -84)
        p.drawPath(cheek)
        p.setBrush(self._ink)
        p.drawRoundedRect(QRectF(-37, -106, 74, 21), 10, 10)
        p.drawEllipse(QPointF(0, -67), 4, 3.2)

    def _eyes(self, p: QPainter, now: float, mood: str, happy: bool, look: Tuple[float, float], squint: float) -> None:
        y = {"kalkan": -95, "ajan": -93, "tilki": -95.5}.get(self.kind, -95)
        gap = 14
        color = self._bad if mood == "alert" else self._eye
        centers = [QPointF(sign * gap + look[0], y + look[1]) for sign in (-1, 1)]
        if happy and mood != "alert":
            p.setBrush(Qt.BrushStyle.NoBrush)
            p.setPen(QPen(color, 3, cap=Qt.PenCapStyle.RoundCap))
            for c in centers:
                arc = QPainterPath(QPointF(c.x() - 6, c.y() + 3))
                arc.quadTo(c.x(), c.y() - 8, c.x() + 6, c.y() + 3)
                p.drawPath(arc)
            return
        blink = 0.12 if (now % 4.3) < 0.14 else 1.0
        height = (14 if mood == "alert" else 11) * blink * (1 - squint)
        p.setPen(Qt.PenStyle.NoPen)
        for c in centers:
            glow = QRadialGradient(c, 12)
            tint = QColor(color)
            tint.setAlphaF(0.35)
            glow.setColorAt(0, tint)
            glow.setColorAt(1, QColor(0, 0, 0, 0))
            p.setBrush(glow)
            p.drawEllipse(c, 12, 12)
            p.setBrush(color)
            p.drawRoundedRect(QRectF(c.x() - 5, c.y() - height / 2, 10, height), 4, 4)

    def _safe(self, p: QPainter, now: float, presence: float, dial: float, mood: str, engage: float) -> None:
        p.save()
        p.translate((1 - presence) * 70, 0)
        p.setOpacity(_clamp(presence * 1.5))
        p.setPen(QPen(self._ink, 2.6))
        p.setBrush(self._metal_dark)
        p.drawRoundedRect(QRectF(160, GROUND - 7, 12, 7), 2, 2)
        p.drawRoundedRect(QRectF(208, GROUND - 7, 12, 7), 2, 2)
        box = QLinearGradient(150, 92, 230, 170)
        box.setColorAt(0, self._metal.lighter(125))
        box.setColorAt(1, self._metal_dark)
        p.setBrush(box)
        p.drawRoundedRect(QRectF(150, 92, 80, 78), 7, 7)
        p.setPen(QPen(self._ink, 1.8))
        p.setBrush(self._metal)
        p.drawRoundedRect(QRectF(157, 99, 66, 64), 4, 4)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(self._ink)
        for y in (108, 154):
            p.drawRoundedRect(QRectF(153, y - 5, 6, 10), 2, 2)

        led = self._warn if engage > 0.2 and int(now * 6) % 2 == 0 else self._bad.darker(130)
        if mood == "happy":
            led = self._good
        elif mood == "alert":
            led = self._bad
        halo = QRadialGradient(QPointF(216, 106), 8)
        tint = QColor(led)
        tint.setAlphaF(0.6)
        halo.setColorAt(0, tint)
        halo.setColorAt(1, QColor(0, 0, 0, 0))
        p.setBrush(halo)
        p.drawEllipse(QPointF(216, 106), 8, 8)
        p.setBrush(led)
        p.drawEllipse(QPointF(216, 106), 2.8, 2.8)

        p.translate(DIAL)
        p.setPen(QPen(self._ink, 2.4))
        p.setBrush(self._metal_dark)
        p.drawEllipse(QPointF(0, 0), 19, 19)
        p.rotate(dial)
        p.setPen(QPen(self._light, 1.4))
        for mark in range(12):
            p.rotate(30)
            p.drawLine(QPointF(0, -16), QPointF(0, -18 if mark % 3 else -13.5))
        p.setPen(QPen(self._ink, 1.5))
        p.setBrush(self._light)
        p.drawEllipse(QPointF(0, 0), 10, 10)
        p.setPen(QPen(self._ink, 3, cap=Qt.PenCapStyle.RoundCap))
        p.drawLine(QPointF(0, 0), QPointF(0, -8))
        p.restore()

    def _arms(self, p: QPainter, pose: QTransform, now: float, presence: float, engage: float, mood: str, happy: bool,
              glass_hand: Optional[QPointF]) -> None:
        pixel = self.kind in SPRITES
        shoulder_x, shoulder_y = (54, -48) if pixel else (40, -72)
        rest_x, rest_y = (64, -22) if pixel else (58, -42)
        wave = math.sin(now * 1.4) * 1.5 * self._live
        left = pose.map(QPointF(-rest_x, rest_y + wave))
        right = pose.map(QPointF(rest_x, rest_y - wave))
        if happy or mood == "alert":
            lift = math.sin(now * (14 if mood == "alert" else 9)) * 4
            left = pose.map(QPointF(-rest_x, -100 + lift))
            right = pose.map(QPointF(rest_x, -100 - lift))
        if glass_hand is not None:
            right = glass_hand
        if presence > 0.05:
            orbit = math.radians(self._dial * 0.9)
            target = DIAL + QPointF(math.cos(orbit) * 7 - 10, math.sin(orbit) * 7 + 2)
            right = right + (target - right) * _clamp(presence)
        for sign, hand in ((-1, left), (1, right)):
            shoulder = pose.map(QPointF(sign * shoulder_x, shoulder_y))
            if pixel:
                self._pixel_arm(p, shoulder, hand)
                continue
            mid = (shoulder + hand) / 2 + QPointF(sign * 5, 8)
            arm = QPainterPath(shoulder)
            arm.quadTo(mid, hand)
            p.setBrush(Qt.BrushStyle.NoBrush)
            p.setPen(QPen(self._ink, 9.5, cap=Qt.PenCapStyle.RoundCap))
            p.drawPath(arm)
            p.setPen(QPen(self._accent, 5.5, cap=Qt.PenCapStyle.RoundCap))
            p.drawPath(arm)
            p.setPen(QPen(self._ink, 2))
            p.setBrush(self._light)
            p.drawEllipse(hand, 5.6, 5.6)

    def _pixel_arm(self, p: QPainter, shoulder: QPointF, hand: QPointF) -> None:
        unit = PIXEL_UNIT
        steps = max(1, int(math.hypot(hand.x() - shoulder.x(), hand.y() - shoulder.y()) / (unit * 0.9)))
        p.setRenderHint(QPainter.RenderHint.Antialiasing, False)
        p.setPen(Qt.PenStyle.NoPen)
        for outline in (True, False):
            for index in range(steps + 1):
                point = shoulder + (hand - shoulder) * (index / steps)
                x, y = round(point.x() / unit) * unit, round(point.y() / unit) * unit
                if outline:
                    p.fillRect(QRectF(x - 2, y - 2, unit + 4, unit + 4), self._ink)
                else:
                    p.fillRect(QRectF(x, y, unit, unit), self._light if index == steps else self._accent)
        p.setRenderHint(QPainter.RenderHint.Antialiasing, True)

    def _stethoscope(self, p: QPainter, pose: QTransform, now: float, lean: float) -> None:
        """Bir ucu maskotun kulağında, diğer ucu kasanın kapağında; dinlerken ses halkaları kulağa ilerler."""
        ear = pose.map(QPointF(36, -96))
        disc = QPointF(170, 152)
        tube = QPainterPath(ear)
        tube.cubicTo(ear + QPointF(10, 50), disc + QPointF(-34, 26), disc)
        alpha = _clamp(lean * 1.5)
        color = QColor(self._ink)
        color.setAlphaF(alpha)
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.setPen(QPen(color, 3.6, cap=Qt.PenCapStyle.RoundCap))
        p.drawPath(tube)
        p.setPen(QPen(self._warn, 1.3, cap=Qt.PenCapStyle.RoundCap))
        p.setOpacity(alpha)
        p.drawPath(tube)
        p.setPen(QPen(self._ink, 2))
        p.setBrush(self._light)
        p.drawEllipse(disc, 6, 6)
        p.drawEllipse(ear, 3.6, 3.6)
        for index in range(3):
            phase = (now * 0.8 + index / 3) % 1.0
            point = tube.pointAtPercent(1 - phase)
            pulse = QColor(self._light)
            pulse.setAlphaF(0.9 * math.sin(phase * math.pi) * alpha)
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(pulse)
            p.drawEllipse(point, 3.2, 3.2)
        p.setOpacity(1.0)

    def _sound_text(self, p: QPainter, text: str, at: QPointF, alpha: float) -> None:
        font = QFont()
        font.setPixelSize(11)
        font.setBold(True)
        p.setFont(font)
        color = QColor(self._eye)
        color.setAlphaF(_clamp(alpha))
        p.setPen(color)
        p.drawText(at, text)

    def _glass_tap(self, p: QPainter, at: QPointF, beat: float) -> None:
        """Maskotun içeriden cama vuruşu: dokunduğu yerde halkalar yayılır."""
        p.setBrush(Qt.BrushStyle.NoBrush)
        for radius in (10, 19, 30):
            ring = QColor(self._eye)
            ring.setAlphaF(_clamp(1 - beat * 1.4) * 0.55)
            p.setPen(QPen(ring, 1.6))
            p.drawEllipse(at, radius * (0.5 + beat), radius * (0.5 + beat) * 0.82)
        self._sound_text(p, tr("tık"), at + QPointF(14, -18 - beat * 10), 1 - beat)

    def _click_marks(self, p: QPainter, now: float) -> None:
        for born, drift in self._clicks:
            age = now - born
            if 0 <= age < 0.8:
                self._sound_text(p, tr("klik"), QPointF(180 + drift, 84 - age * 26), 1 - age / 0.8)

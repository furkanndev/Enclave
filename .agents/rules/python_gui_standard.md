# PYTHON GUI AGENT RULES — PROFESSIONAL UI/UX STANDARD

## 1. CORE PRINCIPLES

Build professional, modern, clean, readable, consistent and production-quality Python desktop applications.

Prioritize:
1. Readability
2. Usability
3. Accessibility
4. Layout stability
5. Consistency
6. Visual quality
7. Decorative effects

Never sacrifice usability for visual effects. Avoid generic AI-generated dashboards, excessive neon colors, glowing borders, unnecessary gradients, excessive shadows, flashy animations and oversized decorative elements.

Do not automatically use the same dark neon theme for every project. Choose a restrained and appropriate visual style for the application's purpose. Prefer neutral backgrounds, clear text, subtle borders and one or two carefully selected accent colors.

## 2. INSPECT THE PROJECT BEFORE CODING

Before modifying or creating the UI:

- Inspect the existing project structure, entry point, Python version, GUI framework and dependencies.
- Identify whether the application uses PySide6, PyQt5, PyQt6, Tkinter, CustomTkinter or another GUI framework.
- Inspect existing shared widgets, stylesheets, fonts, layouts and theme configuration.
- Preserve existing business logic, database operations, APIs and working functionality unless a change is explicitly required.
- Do not rewrite the entire application unnecessarily.
- Use the correct styling and layout techniques for the detected GUI framework.
- Do not mix incompatible GUI frameworks or styling methods.
- If the project already has a design system, improve and standardize it instead of creating conflicting styles.

## 3. TYPOGRAPHY AND READABILITY

Use a consistent typography system throughout the application.

Recommended desktop defaults:
- Main window title: 24–30 px.
- Section headings: 18–22 px.
- Body text: 14–16 px.
- Form labels: 14–16 px.
- Buttons: 14–16 px.
- Secondary information: normally 12–14 px.

Avoid text smaller than 12 px unless absolutely necessary.

- Use readable system fonts such as Segoe UI, Arial, Inter or the platform's native UI font when available.
- Set consistent font families, sizes and weights.
- Use adequate line spacing and margins.
- Use bold text selectively to establish hierarchy.
- Never shrink fonts to solve layout overflow.
- Never use low-contrast gray text on gray backgrounds.
- Prevent clipped text, overlapping labels, broken word wrapping and unreadable controls.
- Support operating-system display scaling and high-DPI screens.
- Respect application font scaling and resizing where supported.

## 4. COLOR SYSTEM AND THEMING

Create a consistent theme using reusable color tokens.

Define centralized values for:
- Main window background
- Panel and card backgrounds
- Primary text
- Secondary text
- Borders and separators
- Primary buttons
- Secondary buttons
- Hover and focus states
- Disabled states
- Success, warning and error states
- Input backgrounds and borders
- Selected and unselected controls

Use a restrained palette with neutral surfaces and a clear accent color.

- Do not use neon green, neon purple, electric blue or glowing effects as default styling.
- Do not apply gradients to every button or panel.
- Do not use excessive rounded cards or nested containers.
- Do not use pure black backgrounds and overly bright text everywhere without a deliberate design reason.
- Ensure text, icons, controls and backgrounds have sufficient contrast.
- Target WCAG 2.2 AA contrast where applicable: 4.5:1 for normal text and 3:1 for large text.
- Do not communicate status using color alone.
- Ensure disabled, selected, focused and hovered states remain distinguishable.
- Avoid random colors across different screens.

Use a consistent design language throughout the entire application.

## 5. LAYOUT AND WINDOW MANAGEMENT

Every screen must fit within the available window size and remain usable when the user resizes the window.

- Prefer responsive layouts over manually positioned widgets.
- Avoid absolute positioning and excessive hardcoded coordinates.
- Never depend on fixed window dimensions to make the interface look correct.
- Avoid fixed widget widths and heights unless genuinely necessary.
- Do not use fixed heights for text-containing widgets when their content may grow.
- Use the framework's native layout system correctly.

For PySide6/PyQt:
- Prefer QVBoxLayout, QHBoxLayout, QGridLayout and QFormLayout.
- Set appropriate size policies, minimum sizes and stretch factors.
- Use layouts instead of manually positioning widgets.
- Use QScrollArea for content that can exceed the available space.
- Handle high-DPI scaling appropriately.

For Tkinter/CustomTkinter:
- Prefer grid, pack or other appropriate layout managers.
- Never mix pack and grid within the same parent container.
- Use row and column weights, sticky settings and suitable padding.
- Use scrollable frames for long forms and content.
- Avoid relying on fixed geometry as the only layout strategy.

General requirements:
- Prevent widgets from extending beyond their parent containers.
- Keep all buttons, fields, labels and navigation controls visible and usable.
- Use scrolling within the appropriate content region when necessary.
- Keep important actions accessible.
- Ensure long forms and large tables remain usable.
- Support small, medium and large window sizes.
- Ensure modal dialogs fit within the available screen.
- Do not solve overflow by hiding content, shrinking fonts or making controls tiny.
- Prevent accidental horizontal scrolling where it is unnecessary.
- Use sensible minimum window sizes without preventing normal resizing.

## 6. BUTTONS AND ACTION CONTROLS

Buttons must be readable, consistent, correctly sized and visually distinct according to their purpose.

- Use approximately 40–44 px as the default minimum height for standard desktop action buttons where appropriate.
- Provide sufficient horizontal padding.
- Use readable 14–16 px text.
- Do not allow labels to be clipped or awkwardly wrapped.
- Ensure buttons fit within their parent layout.
- Use flexible sizing, wrapping or stacked layouts when horizontal space is insufficient.
- Distinguish primary, secondary, neutral and destructive actions.
- Avoid neon fills, excessive outlines, glow effects and unnecessary gradients.
- Keep button styles consistent across all screens.
- Provide clear hover, pressed, keyboard-focus, disabled and loading states.
- Use descriptive button labels instead of unexplained icons.
- Ensure icon-only buttons have accessible labels or tooltips.
- Do not place essential actions outside the visible dialog or window.
- Do not allow button rows to push other important content outside the viewport.

## 7. RADIO BUTTONS, CHECKBOXES AND FORM CONTROLS

Radio buttons, checkboxes, dropdowns and input fields must always be easy to read and operate.

- Keep each control visually aligned with its label.
- Use readable 14–16 px labels.
- Make radio indicators and checkboxes clearly visible against their backgrounds.
- Use appropriate control sizes and generous clickable areas.
- Aim for at least a 40 px interactive row height when the layout permits.
- Keep sufficient spacing between options.
- Make selected and unselected states immediately distinguishable.
- Ensure disabled and focused states are also clear.
- Never place text over controls or allow labels to overlap neighboring widgets.
- Allow long labels to wrap naturally.
- Ensure labels are not clipped by fixed-height containers.
- Where supported, clicking a label should activate the associated control.
- Group related choices with clear headings.
- Use appropriate form layouts for label-field alignment.
- Avoid cramped forms with excessive numbers of controls on one row.
- Do not use low-contrast borders or indicators.
- Preserve keyboard navigation and logical tab order.

## 8. INPUT FIELDS, TABLES AND DATA VIEWS

- Use readable input text and placeholders.
- Keep input fields sufficiently tall for their font size.
- Ensure placeholders are not the only source of field labels.
- Provide visible focus and validation states.
- Display validation errors clearly and close to the relevant field.
- Avoid cutting off important values.
- Use appropriate column sizing in tables.
- Make table headers readable and aligned.
- Prevent buttons and cell contents from overlapping.
- Add scrolling to large datasets.
- Use sorting, filtering and pagination where useful.
- Keep empty states and loading states informative.
- Preserve correct data editing, saving and selection behavior.

## 9. DIALOGS, MODALS AND PANELS

- Use sensible dialog dimensions based on their content.
- Keep dialogs within the available screen area.
- Provide internal scrolling for long content.
- Keep primary and secondary actions in a consistent location.
- Prevent action buttons from being clipped at the bottom.
- Keep padding and spacing consistent.
- Avoid unnecessarily nested dialogs and panels.
- Use clear titles and meaningful close controls.
- Ensure resizing does not break the layout.
- Avoid oversized dialogs containing excessive empty space.

## 10. SPACING AND VISUAL HIERARCHY

Use a consistent spacing scale, for example:
4, 8, 12, 16, 24 and 32 px.

- Align headings, labels, fields, buttons and panels consistently.
- Keep related elements together.
- Separate unrelated sections with appropriate spacing.
- Avoid overcrowded interfaces.
- Avoid excessive empty space that wastes usable window area.
- Use borders and separators sparingly.
- Avoid placing every widget inside a separate card.
- Use clear visual hierarchy instead of excessive colors or decorative effects.

## 11. REUSABLE COMPONENTS AND CODE QUALITY

- Create reusable components for common buttons, form fields, dialogs, tables and navigation elements where appropriate.
- Centralize theme colors, typography, spacing, radii and common styles.
- Keep styles separate from business logic when practical.
- Avoid duplicated and conflicting style definitions.
- Do not create different versions of the same component unnecessarily.
- Fix shared component defects at their source.
- Avoid applying temporary one-off CSS or stylesheet patches to compensate for broken layouts.
- Keep the code maintainable and compatible with the project's existing framework.
- Use clear names and appropriate separation of responsibilities.
- Avoid unnecessary dependencies.
- Do not remove existing features when refactoring the UI.
- Preserve application behavior while improving its presentation.

## 12. FRAMEWORK-SPECIFIC IMPLEMENTATION

Use the appropriate methods for the detected framework.

PySide6 / PyQt:
- Use Qt layouts, size policies, layouts' margins and spacing, and appropriate size constraints.
- Use Qt Style Sheets consistently where appropriate.
- Use QScrollArea for overflowing content.
- Use proper widget size policies instead of forcing every widget to a fixed size.
- Handle dialogs, signals, slots, and widget ownership correctly.
- Verify high-DPI behavior and screen scaling.

Tkinter:
- Use grid or pack consistently within each parent.
- Configure row and column weights.
- Use ttk widgets and ttk.Style where appropriate.
- For CustomTkinter, use its supported appearance modes, fonts, colors and widget configuration.
- Use suitable scrollable containers for large forms.
- Avoid relying on hardcoded geometry for every widget.

Other Python GUI frameworks:
- Follow the framework's native layout, styling, accessibility and scaling conventions.
- Do not copy framework-specific code into an incompatible application.

## 13. ACCESSIBILITY AND INTERACTION

- Support keyboard navigation.
- Provide visible focus indicators.
- Use meaningful accessible labels.
- Ensure controls do not depend solely on color or hover.
- Use appropriate text contrast.
- Keep tab order logical.
- Ensure important actions are discoverable.
- Provide feedback for successful, failed and ongoing operations.
- Prevent accidental duplicate submissions when appropriate.
- Keep essential information visible without requiring tooltips.

## 14. MANDATORY VISUAL TESTING

Do not consider a UI task finished simply because the code compiles.

After implementing or modifying the interface:

1. Run the application when the environment permits.
2. Inspect the actual rendered interface.
3. Check every affected screen and dialog.
4. Test the smallest reasonable window size.
5. Test a normal desktop size and a larger window.
6. Resize windows to detect broken layouts.
7. Check for clipped text, overlapping widgets and overflowing buttons.
8. Verify font sizes, alignment, contrast and spacing.
9. Test radio buttons, checkboxes, dropdowns, inputs and button states.
10. Check scrolling and dialog action visibility.
11. Verify high-DPI and display scaling behavior where possible.
12. Test keyboard navigation where applicable.
13. Confirm that existing business logic and interactions still work.
14. Run available tests, linting and build checks.
15. Fix all detected defects before declaring the task complete.

If screenshot or GUI automation tools are available, use them to inspect the rendered interface. Do not claim visual testing was performed if the application could not actually be launched or inspected.

## 15. HOW TO FIX UI DEFECTS

When an existing interface has problems:

- Identify the root cause before making changes.
- Fix the shared layout, component, font or theme responsible for the issue.
- Do not simply reduce font size.
- Do not hide overflowing controls.
- Do not add arbitrary fixed dimensions to force a widget into place.
- Do not introduce more neon colors or decorative effects to cover visual inconsistencies.
- Do not duplicate styles across multiple files to fix the same defect.
- Verify that the fix works on other screens using the same component.
- Recheck the application after each significant layout or theme change.

## 16. FINAL ACCEPTANCE CRITERIA

A screen is complete only when:

- Text is readable.
- Radio buttons and checkboxes are clearly visible.
- Buttons fit within their containers.
- No important content is clipped or overlapping.
- Layouts respond correctly to window resizing.
- Colors and typography are consistent.
- Contrast and focus states are appropriate.
- Scrolling works where needed.
- The interface looks professional without excessive decoration.
- Existing application functionality is preserved.
- Visual testing has been performed when the environment allows it.

FINAL PRIORITY:
Readability > Usability > Accessibility > Layout Stability > Consistency > Decoration.

When visual styling conflicts with usability, always prioritize usability. Never default to a neon dashboard aesthetic. Build interfaces that look deliberately designed, feel consistent and remain readable under real-world usage.


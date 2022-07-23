use crate::{
    time::Instant,
    ui::{
        component::{
            text::{layout::DefaultTextTheme, paragraphs::Paragraphs},
            Child, Component, ComponentExt, Event, EventCtx, Label, LabelStyle,
        },
        display::{Color, Font},
        geometry::{Alignment, LinearPlacement, Offset, Point, Rect},
        model_tr::{
            component::{Button, ButtonMsg, ButtonPos, ResultAnim, ResultAnimMsg},
            theme,
            theme::{TRDefaultText, FONT_BOLD, FONT_MEDIUM},
        },
    },
};

pub enum ResultPopupMsg {
    Confirmed,
}

pub enum State {
    Initial,
    Animating,
    AnimationDone,
}

pub struct ResultPopup {
    area: Rect,
    state: State,
    result_anim: Child<ResultAnim>,
    headline_baseline: Point,
    headline: Option<Label<&'static str>>,
    text: Child<Paragraphs<&'static str>>,
    button: Option<Child<Button<&'static str>>>,
    autoclose: bool,
}

pub struct MessageText;

impl DefaultTextTheme for MessageText {
    const BACKGROUND_COLOR: Color = theme::BG;
    const TEXT_FONT: Font = FONT_MEDIUM;
    const TEXT_COLOR: Color = theme::FG;
    const HYPHEN_FONT: Font = FONT_MEDIUM;
    const HYPHEN_COLOR: Color = theme::FG;
    const ELLIPSIS_FONT: Font = FONT_MEDIUM;
    const ELLIPSIS_COLOR: Color = theme::FG;

    const NORMAL_FONT: Font = FONT_MEDIUM;
    const MEDIUM_FONT: Font = theme::FONT_MEDIUM;
    const BOLD_FONT: Font = theme::FONT_BOLD;
    const MONO_FONT: Font = theme::FONT_MONO;
}

impl ResultPopup {
    pub fn new(
        icon: &'static [u8],
        text: &'static str,
        headline: Option<&'static str>,
        button_text: Option<&'static str>,
    ) -> Self {
        let p1 = Paragraphs::new()
            .add::<TRDefaultText>(FONT_MEDIUM, text)
            .with_placement(LinearPlacement::vertical().align_at_start());

        let button = button_text.map(|t| {
            Child::new(Button::with_text(
                ButtonPos::Right,
                t,
                theme::button_default(),
            ))
        });

        let headline_style = LabelStyle {
            background_color: theme::BG,
            text_color: theme::FG,
            font: FONT_BOLD,
        };

        Self {
            area: Rect::zero(),
            state: State::Initial,
            result_anim: Child::new(ResultAnim::new(icon)),
            headline: headline.map(|a| Label::new(a, Alignment::Center, headline_style)),
            headline_baseline: Point::zero(),
            text: Child::new(p1),
            button,
            autoclose: false,
        }
    }

    // autoclose even if button is used
    pub fn autoclose(&mut self) {
        self.autoclose = true;
    }

    pub fn start(&mut self, ctx: &mut EventCtx) {
        self.state = State::Animating;
        self.text.request_complete_repaint(ctx);

        if let Some(h) = self.headline.as_mut() {
            h.request_complete_repaint(ctx)
        }

        if let Some(b) = self.button.as_mut() {
            b.request_complete_repaint(ctx)
        }

        self.result_anim.mutate(ctx, |ctx, c| {
            let now = Instant::now();
            c.start_growing(ctx, now);
        });
        ctx.request_paint();
    }
}

impl Component for ResultPopup {
    type Msg = ResultPopupMsg;

    fn place(&mut self, bounds: Rect) -> Rect {
        self.area = bounds;

        let button_area_start = bounds.y1 - 13;
        let mut text_start = bounds.y0 + 64;
        let mut text_end = bounds.y1;

        let mut anim_pos_y = bounds.y0 + 36;

        if let Some(b) = self.button.as_mut() {
            let b_pos = Rect::new(
                Point::new(bounds.x0, button_area_start),
                Point::new(bounds.x1, bounds.y1),
            );
            b.place(b_pos);

            text_start = bounds.y0 + 58;
            text_end = button_area_start;
            anim_pos_y = bounds.y0 + 30;
        };

        if self.headline.is_some() {
            self.headline_baseline = Point::new(
                self.area.center().x,
                self.area.x0 + 54 + 16 - ((16 - FONT_BOLD.text_height()) / 2),
            );
            text_start = bounds.y0 + 74;
            anim_pos_y = bounds.y0 + 26;
        }

        self.text.place(Rect::new(
            Point::new(bounds.x0, text_start),
            Point::new(bounds.x1, text_end),
        ));

        self.result_anim.place(Rect::from_center_and_size(
            Point::new(bounds.center().x, anim_pos_y),
            Offset::new(18, 18),
        ));

        self.area
    }

    fn event(&mut self, ctx: &mut EventCtx, event: Event) -> Option<Self::Msg> {
        let mut button_confirmed = false;

        self.text.event(ctx, event);

        if let Some(h) = self.headline.as_mut() {
            h.event(ctx, event);
        }

        if let Some(b) = self.button.as_mut() {
            if let Some(ButtonMsg::Clicked) = b.event(ctx, event) {
                button_confirmed = true;
            }
        };

        if let Some(ResultAnimMsg::FullyGrown) = self.result_anim.event(ctx, event) {
            self.state = State::AnimationDone;
            if self.button.is_none() || self.autoclose {
                return Some(ResultPopupMsg::Confirmed);
            }
        }

        if button_confirmed {
            return Some(ResultPopupMsg::Confirmed);
        }

        None
    }

    fn paint(&mut self) {
        self.text.paint();

        if let Some(b) = self.button.as_mut() {
            b.paint();
        }

        if let Some(h) = self.headline.as_mut() {
            h.paint();
        }

        self.result_anim.paint();
    }
}

#[cfg(feature = "ui_debug")]
impl crate::trace::Trace for ResultPopup {
    fn trace(&self, d: &mut dyn crate::trace::Tracer) {
        d.open("ResultPopup");
        self.text.trace(d);
        self.button.trace(d);
        //self.headline.trace(d);
        self.result_anim.trace(d);
        d.close();
    }
}

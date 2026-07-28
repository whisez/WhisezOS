//! The assistant: questions about the machine, answered from the machine.
//!
//! # What this is not
//!
//! It is not a language model and it must never be presented as one. There is
//! no model here and there cannot be: the weights of the smallest useful one are
//! larger than this disk, there is no floating point (the target is built
//! `+soft-float, -sse`), and there is nothing to load a model file with. A
//! window that answered in a model's voice would be a lie told by the operating
//! system about itself, which is the worst place to put one.
//!
//! What it is: a fixed set of questions the machine can actually answer, matched
//! by the words in them, answered from what the kernel and the disk say right
//! now. The window says so on its first line. Somebody who reads that line knows
//! exactly what they have, which is more than most assistants offer.
//!
//! # Why matching on words rather than on exact commands
//!
//! Because the questions are the point. `uptime` is already a shell command; if
//! the assistant only accepted `uptime` it would be a second, worse shell. It
//! takes "how long has this been running" and "uptime" and "how long up" as the
//! same question, which is the only thing here that behaves like an assistant.

#![allow(dead_code)]

/// The longest question it will look at. Longer ones are answered as unknown
/// rather than truncated, because a truncated question can match a topic the
/// person did not ask about.
pub const QUESTION_LIMIT: usize = 76;

/// The longest line an answer may hold.
///
/// Checked by a test here and by a const assertion beside the window geometry,
/// which is what ties the two together: a longer line would be drawn outside
/// the window, and outside the rectangle the redraw clears.
pub const LINE_MAX: usize = 60;

/// What the assistant was asked to do about the machine.
///
/// The answers it can give from its own knowledge are `Say`; anything needing a
/// number from the kernel or the disk is a request to the session, for the same
/// reason `console::Action` is — this file has no syscalls, so every rule in it
/// can be tested without a machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    /// Print these lines.
    Say(&'static [&'static [u8]]),
    /// How long the machine has been up.
    Uptime,
    /// What is running.
    Processes,
    /// What is on the disk.
    Files,
    /// What hardware there is.
    Devices,
    /// Current network state, read by the session.
    Network,
    /// Open one of the desktop tools.
    OpenFiles,
    OpenEditor,
    OpenNetwork,
    OpenDrivers,
    NewText,
    /// Write what follows the keyword into the notes file.
    Remember,
    /// Read the notes file back.
    Recall,
    /// Nothing matched.
    Unknown,
}

/// The file the notes go in. A name somebody could have typed themselves, in a
/// format they can read: the assistant's memory is a file on their disk, not a
/// private store they have to ask it about.
pub const NOTES: &[u8] = b"NOTES.MD";

/// The words that mean the notes file.
///
/// Plurals are listed rather than stemmed. "notes" is not "note" to a
/// whole-word match, and "what are your notes" is the plainest way somebody
/// asks — it reached the who-am-I answer instead, because "you" was in it.
const MEMORY_WORDS: [&[u8]; 7] = [
    b"remember",
    b"note",
    b"notes",
    b"memorise",
    b"hatirla",
    b"notlar",
    b"kaydet",
];

/// What to write down, out of a question that asks for something to be.
///
/// Everything after the keyword, trimmed. `None` when the question is not about
/// memory at all; empty when it is a question *about* the notes rather than an
/// instruction to add to them — "what do you remember" ends at the keyword, and
/// storing an empty note for it would be the wrong answer to a fair question.
#[must_use]
pub fn remembered_text(question: &[u8]) -> Option<&[u8]> {
    for keyword in MEMORY_WORDS {
        if let Some(at) = word_end(question, keyword) {
            return Some(trim(&question[at..]));
        }
    }
    None
}

/// Where a whole word ends in a question, if it is there.
fn word_end(question: &[u8], word: &[u8]) -> Option<usize> {
    let mut at = 0;
    while at < question.len() {
        if !is_letter(question[at]) {
            at += 1;
            continue;
        }
        let start = at;
        while at < question.len() && is_letter(question[at]) {
            at += 1;
        }
        let found = &question[start..at];
        if found.len() == word.len()
            && found
                .iter()
                .zip(word.iter())
                .all(|(a, b)| lower(*a) == lower(*b))
        {
            return Some(at);
        }
    }
    None
}

/// Drops spaces and punctuation from both ends of a note.
fn trim(text: &[u8]) -> &[u8] {
    let mut start = 0;
    let mut end = text.len();
    while start < end && matches!(text[start], b' ' | b'\t' | b':' | b',') {
        start += 1;
    }
    while end > start && matches!(text[end - 1], b' ' | b'\t' | b'.' | b'?' | b'!') {
        end -= 1;
    }
    &text[start..end]
}

/// A topic: the words that reach it, and what it answers.
struct Topic {
    /// Any one of these in the question selects the topic. Whole words, so that
    /// "software" does not match a topic keyed on "soft".
    words: &'static [&'static [u8]],
    answer: Answer,
}

/// What it knows.
///
/// Ordered by how specific the topic is, and matched in that order, so that a
/// question mentioning two topics gets the narrower one. "how much disk space is
/// free" names both storage and the machine; the storage answer is the one that
/// was asked for.
const TOPICS: &[Topic] = &[
    Topic {
        words: &[b"uptime", b"long", b"running", b"sure", b"acik"],
        answer: Answer::Uptime,
    },
    Topic {
        words: &[b"process", b"processes", b"tasks", b"surec", b"gorev"],
        answer: Answer::Processes,
    },
    Topic {
        words: &[
            b"file",
            b"files",
            b"folder",
            b"folders",
            b"disk",
            b"ls",
            b"dosya",
            b"dosyalar",
            b"klasor",
        ],
        answer: Answer::Files,
    },
    Topic {
        words: &[
            b"device",
            b"devices",
            b"hardware",
            b"sound",
            b"mouse",
            b"aygit",
            b"donanim",
            b"ses",
            b"fare",
            b"surucu",
        ],
        answer: Answer::Devices,
    },
    Topic {
        words: &[b"who", b"you", b"yourself", b"kimsin", b"nesin"],
        answer: Answer::Say(&[
            b"I am not a language model and there is none here.",
            b"Ben yerel WhisezOS sistem asistaninin ilk surumuyum.",
            b"Kernel, disk, ag ve surucu durumunu okuyabilirim.",
            b"Sor: sistem, dosyalar, ag, suruculer, yardim.",
        ]),
    },
    Topic {
        words: &[b"memory", b"ram", b"free", b"bellek", b"bos"],
        answer: Answer::Say(&[
            b"The kernel does not report free memory to ring 3 yet.",
            b"The task manager shows DMA regions and device",
            b"mappings per process, which is what it does report.",
        ]),
    },
    Topic {
        words: &[
            b"internet",
            b"internete",
            b"internette",
            b"network",
            b"wifi",
            b"ip",
            b"browser",
            b"ag",
            b"baglanti",
            b"baglan",
            b"bagli",
            b"cevrimici",
            b"online",
        ],
        answer: Answer::Network,
    },
    Topic {
        words: &[b"help", b"can", b"do", b"yardim", b"yapabilirsin"],
        answer: Answer::Say(&[
            b"Dosyalari, Not Defteri'ni, agi ve suruculeri acabilirim.",
            b"Sistem suresi, gorevler, donanim ve agi sorabilirsin.",
            b"English: files, network, devices, uptime, help.",
        ]),
    },
];

/// Reads a question.
///
/// Case is ignored and punctuation is not a word boundary problem, because the
/// question is split on anything that is not a letter — somebody typing "what's
/// running?" should not be told to try again without the question mark.
#[must_use]
pub fn ask(question: &[u8]) -> Answer {
    if question.len() > QUESTION_LIMIT {
        return Answer::Unknown;
    }
    // Checked before the topics, because a note can be about anything and would
    // otherwise be answered as whatever it happens to mention. "remember that
    // the disk is nearly full" is not a question about the disk.
    if let Some(text) = remembered_text(question) {
        return if text.is_empty() {
            Answer::Recall
        } else {
            Answer::Remember
        };
    }
    let open = has_any(question, &[b"open", b"show", b"ac", b"goster"]);
    if open
        && has_any(
            question,
            &[b"notepad", b"editor", b"metin", b"notdefteri", b"not"],
        )
    {
        return Answer::OpenEditor;
    }
    if open
        && has_any(
            question,
            &[
                b"file",
                b"files",
                b"folder",
                b"dosya",
                b"dosyalari",
                b"klasor",
            ],
        )
    {
        return Answer::OpenFiles;
    }
    if open && has_any(question, &[b"network", b"internet", b"ag", b"baglanti"]) {
        return Answer::OpenNetwork;
    }
    if open
        && has_any(
            question,
            &[
                b"driver",
                b"drivers",
                b"surucu",
                b"suruculer",
                b"suruculeri",
            ],
        )
    {
        return Answer::OpenDrivers;
    }
    if has_any(question, &[b"new", b"create", b"yeni", b"olustur"])
        && has_any(question, &[b"text", b"txt", b"metin", b"dosya"])
    {
        return Answer::NewText;
    }
    for topic in TOPICS {
        for word in topic.words {
            if contains_word(question, word) {
                return topic.answer;
            }
        }
    }
    Answer::Unknown
}

fn has_any(question: &[u8], words: &[&[u8]]) -> bool {
    words.iter().any(|word| contains_word(question, word))
}

/// Whether a question contains a word, as a whole word and ignoring case.
///
/// Whole-word rather than substring: keyed on "can", a substring match would
/// fire on "cancel" and on "scan", and the answer would arrive for a question
/// nobody asked.
#[must_use]
pub fn contains_word(question: &[u8], word: &[u8]) -> bool {
    let mut at = 0;
    while at < question.len() {
        if !is_letter(question[at]) {
            at += 1;
            continue;
        }
        let start = at;
        while at < question.len() && is_letter(question[at]) {
            at += 1;
        }
        let found = &question[start..at];
        if found.len() == word.len()
            && found
                .iter()
                .zip(word.iter())
                .all(|(a, b)| lower(*a) == lower(*b))
        {
            return true;
        }
    }
    false
}

const fn is_letter(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
}

const fn lower(byte: u8) -> u8 {
    byte.to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_answers_the_question_it_was_asked() {
        assert_eq!(ask(b"uptime"), Answer::Uptime);
        assert_eq!(ask(b"what processes are there"), Answer::Processes);
        assert_eq!(ask(b"what files are on disk"), Answer::Files);
        assert_eq!(ask(b"what devices does this have"), Answer::Devices);
    }

    #[test]
    fn the_same_question_asked_differently_is_the_same_question() {
        // The one thing here that behaves like an assistant rather than like a
        // second shell.
        for phrasing in [
            &b"uptime"[..],
            b"how long has this been running",
            b"HOW LONG UP",
            b"uptime?",
        ] {
            assert_eq!(ask(phrasing), Answer::Uptime, "{phrasing:?}");
        }
    }

    #[test]
    fn punctuation_does_not_hide_a_word() {
        assert_eq!(ask(b"what's running?"), Answer::Uptime);
        assert_eq!(ask(b"files!"), Answer::Files);
    }

    #[test]
    fn a_word_inside_another_word_does_not_match() {
        // Keyed on "can", a substring match fires on "cancel" and on "scan",
        // and an answer arrives for a question nobody asked.
        assert_eq!(ask(b"cancel"), Answer::Unknown);
        assert_eq!(ask(b"scandinavia"), Answer::Unknown);
        // And "disk" must not be found inside "diskette-shaped".
        assert!(!contains_word(b"diskette", b"disk"));
    }

    #[test]
    fn it_says_it_is_not_a_language_model_when_asked_what_it_is() {
        // The one answer that must never drift. Somebody asking what this is
        // deserves the true answer in the first line of it.
        let Answer::Say(lines) = ask(b"who are you") else {
            panic!("the assistant would not say what it is");
        };
        assert!(
            lines[0].windows(14).any(|w| w == b"language model"),
            "the first line does not say what it is not"
        );
    }

    #[test]
    fn network_questions_ask_the_session_for_live_state() {
        assert_eq!(ask(b"can I get on the internet"), Answer::Network);
        assert_eq!(ask(b"ag baglantisi var mi"), Answer::Network);
        assert_eq!(ask(b"internete bagli miyim"), Answer::Network);
        assert_eq!(ask(b"su an internette miyim"), Answer::Network);
    }

    #[test]
    fn turkish_questions_and_desktop_actions_are_understood() {
        assert_eq!(ask(b"sistem ne kadar suredir acik"), Answer::Uptime);
        assert_eq!(ask(b"dosyalari goster"), Answer::OpenFiles);
        assert_eq!(ask(b"not defterini ac"), Answer::OpenEditor);
        assert_eq!(ask(b"suruculeri goster"), Answer::OpenDrivers);
        assert_eq!(ask(b"yeni metin dosyasi olustur"), Answer::NewText);
    }

    #[test]
    fn every_memory_word_on_its_own_asks_for_the_notes() {
        // A word in the list that some earlier rule claims is a word that looks
        // like it works and does not.
        for word in MEMORY_WORDS {
            assert_eq!(
                ask(word),
                Answer::Recall,
                "{:?} does not reach the notes",
                core::str::from_utf8(word).unwrap_or("?")
            );
        }
    }

    #[test]
    fn it_writes_down_what_it_is_asked_to_remember() {
        assert_eq!(ask(b"remember the disk is nearly full"), Answer::Remember);
        assert_eq!(
            remembered_text(b"remember the disk is nearly full"),
            Some(&b"the disk is nearly full"[..])
        );
    }

    #[test]
    fn a_note_is_taken_whole_even_when_it_names_a_topic() {
        // "remember that the disk is nearly full" is not a question about the
        // disk. Answering it as one would file the note as a directory listing.
        assert_eq!(ask(b"note: the disk holds the backups"), Answer::Remember);
        assert_eq!(ask(b"remember to check the files"), Answer::Remember);
        assert_eq!(
            remembered_text(b"note: the disk holds the backups"),
            Some(&b"the disk holds the backups"[..])
        );
    }

    #[test]
    fn asking_what_it_remembers_is_not_a_note() {
        // The question ends at the keyword, so there is nothing to write down —
        // and storing an empty note would be the wrong answer to a fair
        // question.
        for phrasing in [
            &b"what do you remember"[..],
            b"remember?",
            b"what are your notes",
        ] {
            assert_eq!(ask(phrasing), Answer::Recall, "{phrasing:?}");
        }
    }

    #[test]
    fn the_notes_go_in_a_file_somebody_could_have_made_themselves() {
        // The assistant's memory is a file on their disk in a format they can
        // read, not a private store they have to ask it about.
        assert!(NOTES.ends_with(b".MD"));
        assert!(crate::dir::name_ok(NOTES), "the disk would refuse the name");
    }

    #[test]
    fn a_question_it_cannot_answer_is_not_answered() {
        // The failure worth guarding: a matcher loose enough to find a topic in
        // anything would answer every question, and confidently.
        for question in [
            &b"write me a poem about the sea"[..],
            b"what is the capital of France",
            b"solve x squared plus two x",
            b"",
        ] {
            assert_eq!(ask(question), Answer::Unknown, "{question:?}");
        }
    }

    #[test]
    fn an_overlong_question_is_refused_rather_than_cut_short() {
        // A truncated question can match a topic the person did not ask about.
        let long = [b'a'; QUESTION_LIMIT + 1];
        assert_eq!(ask(&long), Answer::Unknown);
    }

    #[test]
    fn every_word_reaches_the_topic_it_is_listed_under() {
        // Per word, not per topic. A word claimed by an earlier topic still
        // sits in the list looking like it does something — the first version
        // had "running?" under processes, which the splitter can never produce
        // because it stops at the question mark, and "running" under uptime,
        // which would have shadowed it anyway. Both read as coverage of a
        // question the assistant could not actually answer.
        for topic in TOPICS {
            for word in topic.words {
                assert_eq!(
                    ask(word),
                    topic.answer,
                    "a word does not reach its own topic: {:?}",
                    core::str::from_utf8(word).unwrap_or("?")
                );
            }
        }
    }

    #[test]
    fn every_topic_has_words_and_every_answer_has_lines() {
        for topic in TOPICS {
            assert!(!topic.words.is_empty());
            for word in topic.words {
                assert!(!word.is_empty());
            }
            if let Answer::Say(lines) = topic.answer {
                assert!(!lines.is_empty(), "a topic answers with nothing");
                for line in lines {
                    assert!(!line.is_empty());
                    assert!(line.len() <= LINE_MAX, "a line will not fit the window");
                }
            }
        }
    }
}

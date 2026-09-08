from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one match, got {count}")
    return text.replace(old, new, 1)


path = Path("crates/smb-stream/src/broker.rs")
text = path.read_text()

text = replace_once(
    text,
    """    background_command: watch::Receiver<Option<PrefetchCommand>>,
    source: Option<BrokerSource<T>>,
""",
    """    background_command: watch::Receiver<Option<PrefetchCommand>>,
    background_sender: watch::Sender<Option<PrefetchCommand>>,
    source: Option<BrokerSource<T>>,
""",
    "runner background sender field",
)

text = replace_once(
    text,
    """                    let _ = reply.send(result);
                    if let Some(command) = auto_prefetch {
                        let _ = self.process_prefetch(command).await;
                    }
""",
    """                    let _ = reply.send(result);
                    if let Some(command) = auto_prefetch {
                        self.background_sender.send_replace(Some(command));
                    }
""",
    "defer automatic prefetch",
)

text = replace_once(
    text,
    """        interactive_commands: interactive_tx,
        background_command: background_tx,
        file_len,
""",
    """        interactive_commands: interactive_tx,
        background_command: background_tx.clone(),
        file_len,
""",
    "clone background sender for handle",
)

text = replace_once(
    text,
    """        interactive_commands: interactive_rx,
        background_command: background_rx,
        source: Some(source),
""",
    """        interactive_commands: interactive_rx,
        background_command: background_rx,
        background_sender: background_tx,
        source: Some(source),
""",
    "store background sender in runner",
)

path.write_text(text)

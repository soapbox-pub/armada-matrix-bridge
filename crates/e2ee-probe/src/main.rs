//! An end-to-end encrypting Matrix client for testing the bridge's encryption.
//!
//!   e2ee-probe USER PASS create-encrypted INVITEE...   # prints the new room id
//!   e2ee-probe USER PASS send ROOM TEXT
//!   e2ee-probe USER PASS read ROOM SECONDS             # decrypted timeline + sender trust
//!   e2ee-probe USER PASS join ROOM
//!
//! The device persists in /tmp/e2ee-probe-USER, so repeated runs are one device.

use std::time::Duration;

use anyhow::Result;
use matrix_sdk::config::SyncSettings;
use matrix_sdk::deserialized_responses::TimelineEventKind;
use matrix_sdk::ruma::api::client::room::create_room::v3::Request as CreateRoom;
use matrix_sdk::ruma::events::room::encryption::RoomEncryptionEventContent;
use matrix_sdk::ruma::events::room::message::RoomMessageEventContent;
use matrix_sdk::ruma::events::InitialStateEvent;
use matrix_sdk::ruma::{OwnedRoomId, OwnedUserId};
use matrix_sdk::Client;

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let (user, pass, cmd) = (&args[1], &args[2], args[3].as_str());
    let hs = std::env::var("HS").unwrap_or_else(|_| "http://127.0.0.1:8008".into());
    let client = Client::builder().homeserver_url(&hs).sqlite_store(format!("/tmp/e2ee-probe-{user}"), None).build().await?;
    let session = format!("/tmp/e2ee-probe-{user}/session.json");
    if let Ok(saved) = std::fs::read_to_string(&session) {
        let s: matrix_sdk::authentication::matrix::MatrixSession = serde_json::from_str(&saved)?;
        client.restore_session(s).await?;
    } else {
        client.matrix_auth().login_username(user, pass).initial_device_display_name("e2ee-probe").await?;
        std::fs::write(&session, serde_json::to_string(&client.matrix_auth().session().unwrap())?)?;
    }
    client.sync_once(SyncSettings::default().timeout(Duration::from_secs(1))).await?;

    match cmd {
        "create-encrypted" => {
            let mut req = CreateRoom::new();
            req.invite = args[4..].iter().map(|u| u.parse()).collect::<Result<Vec<OwnedUserId>, _>>()?;
            req.initial_state = vec![InitialStateEvent::with_empty_state_key(RoomEncryptionEventContent::with_recommended_defaults()).to_raw_any()];
            let room = client.create_room(req).await?;
            println!("{}", room.room_id());
        }
        "join" => {
            let room: OwnedRoomId = args[4].parse()?;
            client.join_room_by_id(&room).await?;
            client.sync_once(SyncSettings::default().timeout(Duration::from_secs(1))).await?;
        }
        "send" => {
            let room = client.get_room(&args[4].parse::<OwnedRoomId>()?).expect("joined room");
            // Make sure we know everyone's devices before encrypting.
            client.sync_once(SyncSettings::default().timeout(Duration::from_secs(1))).await?;
            let res = room.send(RoomMessageEventContent::text_plain(&args[5])).await?;
            println!("{}", res.response.event_id);
        }
        "read" => {
            let secs: u64 = args[5].parse()?;
            let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
            while tokio::time::Instant::now() < deadline {
                client.sync_once(SyncSettings::default().timeout(Duration::from_secs(2))).await?;
            }
            let room = client.get_room(&args[4].parse::<OwnedRoomId>()?).expect("joined room");
            let messages = room.messages(matrix_sdk::room::MessagesOptions::backward()).await?;
            for ev in messages.chunk.iter().rev() {
                let json: serde_json::Value = ev.raw().deserialize_as()?;
                let trust = match &ev.kind {
                    TimelineEventKind::Decrypted(d) => format!("decrypted, sender device verified: {:?}", d.encryption_info.verification_state),
                    TimelineEventKind::UnableToDecrypt { .. } => "UNABLE TO DECRYPT".into(),
                    TimelineEventKind::PlainText { .. } => "plaintext".into(),
                };
                if json["type"] == "m.room.message" || json["type"] == "m.room.encrypted" {
                    println!("{} {} {} [{trust}]", json["sender"], json["type"], json["content"]["body"]);
                }
            }
        }
        other => anyhow::bail!("unknown command {other}"),
    }
    Ok(())
}

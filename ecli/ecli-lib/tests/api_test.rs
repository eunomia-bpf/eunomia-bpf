//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!

//! Here tests whether the apis of server & client can work peoperly

use std::{convert::Infallible, net::SocketAddr, str::FromStr, time::Duration};

use ecli_lib::{
    config::ProgramType,
    runner::{
        client::{http::EcliHttpClient, AbstractClient, ProgramStatus},
        server_http::{EcliHttpServerAPI, HttpServerState},
        LogType,
    },
};
use hyper::{
    server::conn::AddrStream,
    service::{make_service_fn, service_fn, Service},
    Body, Request, Server,
};
use std::path::PathBuf;
use tokio::sync::mpsc::Sender;
fn get_local_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests")
}

async fn prepare_server_and_client(port: u16) -> (EcliHttpClient, Sender<()>) {
    let app_state = HttpServerState::default();
    let addr = SocketAddr::from_str(&format!("127.0.0.1:{}", port)).unwrap();
    let server = Server::bind(&addr);
    let server = server.serve(make_service_fn(move |_socket: &AddrStream| {
        let app_state = app_state.clone();
        let mut service = ecli_server_codegen::Service::new(EcliHttpServerAPI {});
        async move {
            Ok::<_, Infallible>(service_fn(move |req: Request<Body>| {
                let app_state = app_state.clone();
                service.call((req, app_state))
            }))
        }
    }));
    let (stop_tx, mut stop_rx) = tokio::sync::mpsc::channel::<()>(1);
    tokio::spawn(async move {
        let server = server.with_graceful_shutdown(async move {
            stop_rx.recv().await;
        });
        server.await.unwrap();
    });

    let client = EcliHttpClient::new(format!("http://127.0.0.1:{}", port)).unwrap();
    (client, stop_tx)
}

#[tokio::test(flavor = "multi_thread")]
async fn test_load_wasm_prog() {
    let (client, stop_tx) = prepare_server_and_client(8562).await;

    // Let's load a wasm program
    let wasm_handle = {
        let buf = std::fs::read(get_local_dir().join("bootstrap.wasm")).unwrap();
        client
            .start_program(
                Some("my-wasm-program".to_string()),
                &buf,
                ProgramType::WasmModule,
                false,
                &[],
                None,
            )
            .await
            .unwrap()
    };
    let progs = client.get_program_list().await.unwrap();
    assert_eq!(progs.len(), 1);
    assert_eq!(progs[0].id, wasm_handle);
    assert_eq!(progs[0].name, "my-wasm-program");
    assert_eq!(progs[0].status, ProgramStatus::Running);

    tokio::time::sleep(Duration::from_secs(5)).await;
    // Let's see the logs
    let mut out_buf = String::default();
    let mut cursor = None;
    for _ in 0..5 {
        let logs = client.fetch_logs(wasm_handle, cursor, None).await.unwrap();
        for (cursor1, log) in logs {
            cursor = Some(cursor1 + 1);
            assert!(!matches!(log.log_type, LogType::Plain));
            out_buf.push_str(log.log.as_str());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    println!("{}", out_buf);
    stop_tx.send(()).await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_load_json_prog() {
    let (client, stop_tx) = prepare_server_and_client(8563).await;

    let json_handle = {
        // Let's load a json program, but let it prints plain text
        let buf = std::fs::read(get_local_dir().join("bootstrap.json")).unwrap();
        client
            .start_program(
                Some("my-json-program".to_string()),
                &buf,
                ProgramType::JsonEunomia,
                false,
                &[],
                None,
            )
            .await
            .unwrap()
    };
    let progs = client.get_program_list().await.unwrap();
    assert_eq!(progs.len(), 1);
    assert_eq!(progs[0].id, json_handle);
    assert_eq!(progs[0].name, "my-json-program");
    assert_eq!(progs[0].status, ProgramStatus::Running);

    tokio::time::sleep(Duration::from_secs(5)).await;
    // Let's see the logs
    let mut out_buf = String::default();
    let mut cursor = None;
    for _ in 0..5 {
        let logs = client.fetch_logs(json_handle, cursor, None).await.unwrap();
        for (cursor1, log) in logs {
            cursor = Some(cursor1 + 1);
            assert!(matches!(log.log_type, LogType::Plain));
            out_buf.push_str(log.log.as_str());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    println!("{}", out_buf);
    stop_tx.send(()).await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_load_json_prog_and_out_json() {
    let (client, stop_tx) = prepare_server_and_client(8564).await;

    let json_handle = {
        // Let's load a json program, but let it prints json
        let buf = std::fs::read(get_local_dir().join("bootstrap.json")).unwrap();
        client
            .start_program(
                Some("my-json-program".to_string()),
                &buf,
                ProgramType::JsonEunomia,
                true,
                &[],
                None,
            )
            .await
            .unwrap()
    };
    let progs = client.get_program_list().await.unwrap();
    assert_eq!(progs.len(), 1);
    assert_eq!(progs[0].id, json_handle);
    assert_eq!(progs[0].name, "my-json-program");
    assert_eq!(progs[0].status, ProgramStatus::Running);

    tokio::time::sleep(Duration::from_secs(5)).await;
    // Let's see the logs
    let mut cursor = None;
    for _ in 0..5 {
        let logs = client.fetch_logs(json_handle, cursor, None).await.unwrap();
        for (cursor1, log) in logs {
            cursor = Some(cursor1 + 1);
            assert!(matches!(log.log_type, LogType::Plain));
            serde_json::from_str::<serde_json::Value>(&log.log).unwrap();
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    stop_tx.send(()).await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_pause_and_resume() {
    let (client, stop_tx) = prepare_server_and_client(8565).await;

    let json_handle = {
        // Let's load a json program, but let it prints plain text
        let buf = std::fs::read(get_local_dir().join("bootstrap.json")).unwrap();
        client
            .start_program(
                Some("my-json-program".to_string()),
                &buf,
                ProgramType::JsonEunomia,
                true,
                &[],
                None,
            )
            .await
            .unwrap()
    };

    tokio::time::sleep(Duration::from_secs(5)).await;
    let mut logs_buf = vec![];
    // Let's see the logs
    let mut cursor = None;
    for _ in 0..5 {
        let logs = client.fetch_logs(json_handle, cursor, None).await.unwrap();
        for (cursor1, log) in logs {
            cursor = Some(cursor1 + 1);
            assert!(matches!(log.log_type, LogType::Plain));
            logs_buf.push(serde_json::from_str::<serde_json::Value>(&log.log).unwrap());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // pause it
    client
        .set_program_pause_state(json_handle, true)
        .await
        .unwrap();
    // Wait for the worker's dying
    tokio::time::sleep(Duration::from_secs(1)).await;
    // Clean caches
    if let Some(v) = client
        .fetch_logs(json_handle, cursor, None)
        .await
        .unwrap()
        .last()
    {
        cursor = Some(v.0 + 1);
    }
    // Wait for 3 seconds
    tokio::time::sleep(Duration::from_secs(3)).await;
    // Then just try to poll
    let curr_len = client
        .fetch_logs(json_handle, cursor, None)
        .await
        .unwrap()
        .len();
    assert_eq!(curr_len, 0);
    // Let it resume
    client
        .set_program_pause_state(json_handle, false)
        .await
        .unwrap();
    // Wait for 3 seconds
    tokio::time::sleep(Duration::from_secs(10)).await;
    // Here must be something
    let curr_len = client
        .fetch_logs(json_handle, cursor, None)
        .await
        .unwrap()
        .len();
    assert_ne!(curr_len, 0);

    stop_tx.send(()).await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_terminate_wasm_program() {
    let (client, stop_tx) = prepare_server_and_client(8566).await;

    let wasm_handle = {
        let buf = std::fs::read(get_local_dir().join("bootstrap.wasm")).unwrap();
        client
            .start_program(
                Some("my-wasm-program".to_string()),
                &buf,
                ProgramType::WasmModule,
                false,
                &[],
                None,
            )
            .await
            .unwrap()
    };
    // Wait for a while
    tokio::time::sleep(Duration::from_secs(3)).await;
    // Terminate it
    client.terminate_program(wasm_handle).await.unwrap();
    let list = client.get_program_list().await.unwrap();
    assert_eq!(list.len(), 0);
    stop_tx.send(()).await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_terminate_json_program() {
    let (client, stop_tx) = prepare_server_and_client(8567).await;

    let json_handle = {
        let buf = std::fs::read(get_local_dir().join("bootstrap.json")).unwrap();
        client
            .start_program(
                Some("my-json-program".to_string()),
                &buf,
                ProgramType::JsonEunomia,
                false,
                &[],
                None,
            )
            .await
            .unwrap()
    };
    // Wait for a while
    tokio::time::sleep(Duration::from_secs(3)).await;
    // Terminate it
    client.terminate_program(json_handle).await.unwrap();
    let list = client.get_program_list().await.unwrap();
    assert_eq!(list.len(), 0);
    stop_tx.send(()).await.unwrap();
}
#[tokio::test(flavor = "multi_thread")]
async fn test_running_multiple_programs() {
    let (client, stop_tx) = prepare_server_and_client(8568).await;
    let json_buf = std::fs::read(get_local_dir().join("bootstrap.json")).unwrap();
    let wasm_buf = std::fs::read(get_local_dir().join("bootstrap.wasm")).unwrap();
    let mut handles = vec![];
    for i in 0..5 {
        let handle = client
            .start_program(
                Some(format!("wasm-program-{}", i + 1)),
                &wasm_buf,
                ProgramType::WasmModule,
                false,
                &[],
                None,
            )
            .await
            .unwrap();
        handles.push(handle);
    }

    for i in 0..5 {
        let handle = client
            .start_program(
                Some(format!("json-program-{}-output-plain", i + 1)),
                &json_buf,
                ProgramType::JsonEunomia,
                false,
                &[],
                None,
            )
            .await
            .unwrap();
        handles.push(handle);
    }

    for i in 0..5 {
        let handle = client
            .start_program(
                Some(format!("json-program-{}-output-json", i + 1)),
                &json_buf,
                ProgramType::JsonEunomia,
                true,
                &[],
                None,
            )
            .await
            .unwrap();
        handles.push(handle);
    }
    // Wait a moment
    tokio::time::sleep(Duration::from_secs(5)).await;
    println!("sleep done");
    // Try to poll logs
    for handle in handles.iter() {
        client.fetch_logs(*handle as u64, None, None).await.unwrap();
    }
    println!("fetch logs done");
    // Terminate them
    for handle in handles.iter() {
        client.terminate_program(*handle as u64).await.unwrap();
    }
    println!("terminate done");
    stop_tx.send(()).await.unwrap();
}

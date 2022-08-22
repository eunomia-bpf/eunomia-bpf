/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 *
 * Copyright (c) 2022, 郑昱笙，濮雯旭，张典典（牛校牛子队）
 * All rights reserved.
 */

#ifndef EVENT_HANDLER_H
#define EVENT_HANDLER_H

#include <mutex>
#include <iostream>
#include <string>
#include <thread>
#include <memory>

/// concept for a eunomia event
#if __cplusplus >= 202002L
/// which will be reported by a tracker
template<typename EVENT>
concept event_concept =  requires
{
  /// pid of the associated process
  typename EVENT::pid;
};
#else
#define event_concept typename
#endif

/// the basic event type

/// T is the event from C code
template <typename T>
struct tracker_event
{
    T data;
    // TODO: add more data options here?
};

/// the event handler for share_ptr
template <typename T>
struct event_handler_base
{
public:
    virtual ~event_handler_base() = default;
    virtual void handle(tracker_event<T> &e) = 0;
    virtual void do_handle_event(tracker_event<T> &e) = 0;
};

/// the event handler for single type

/// all single type event hanlder should inherit from this class
template <typename T>
struct event_handler : event_handler_base<T>
{
std::shared_ptr<event_handler_base<T>> next_handler = nullptr;
public:
    virtual ~event_handler() = default;

    /// implement this function to handle the event
    virtual void handle(tracker_event<T> &e) = 0;

    /// add a next handler after this handler
    std::shared_ptr<event_handler<T>> add_handler(std::shared_ptr<event_handler<T>> handler)
    {
        next_handler = handler;
        return handler;
    }
    /// do the handle event
    /// pass the event to next handler
    void do_handle_event(tracker_event<T> &e)
    {
        bool is_catched = false;
        try {
            handle(e);
        } catch (const std::exception& error) {
            // std::cerr << "exception: " << error.what() << std::endl;
            is_catched = true;
        }
        if (!is_catched && next_handler)
            next_handler->do_handle_event(e);
        return;
    }
};

/// Event handler type switcher

/// all switch type event hanlder should inherit from this class
template <typename T1, typename T2>
struct event_handler_adapter : event_handler_base<T2>
{
std::shared_ptr<event_handler_base<T2>> next_handler = nullptr;
public:
    virtual ~event_handler_adapter() = default;
    virtual tracker_event<T1> adapt(tracker_event<T2> &e) = 0;
    std::shared_ptr<event_handler<T1>> add_handler(std::shared_ptr<event_handler<T1>> handler)
    {
        next_handler = handler;
        return handler;
    }
    void do_handle_event(tracker_event<T2> &e)
    {
        auto event1 = adapt(e);
        if (next_handler)
            next_handler->do_handle_event(event1);
        return;
    }
};

#endif

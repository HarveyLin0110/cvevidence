"""Five-step UI navigation; caller supplies states from its validated saved run."""
PAGES = ("01 產品與資料來源", "02 資料確認與缺件", "03 分析進度與結果",
         "04 AI 查核與補件", "05 報告與後續行動")


def availability(*, has_run, failed, has_engineering):
    if not has_run:
        return (True, False, False, False, False)
    if failed:
        return (True, False, False, False, True)
    return (True, True, True, bool(has_engineering), True)


def go(st, page):
    st.session_state.step = page


def sidebar_steps(st, *, has_run, failed=False, has_engineering=False):
    enabled = availability(has_run=has_run, failed=failed, has_engineering=has_engineering)
    previous = st.session_state.get("step", PAGES[0])
    # Preserve existing saved navigation when the old report page was step 04.
    if previous == "04 報告與後續行動": previous = PAGES[4]
    if previous not in PAGES or not enabled[PAGES.index(previous)]:
        previous = PAGES[4] if has_run and failed else PAGES[0]
    st.session_state.step = previous
    for index, page in enumerate(PAGES):
        st.sidebar.button(page, key="workflow-step-" + str(index),
                          type="primary" if page == previous else "secondary",
                          disabled=not enabled[index], on_click=go, args=(st, page),
                          use_container_width=True)
    if not has_run:
        st.sidebar.caption("先建立工程包查核；情境草稿可在第一步繼續補資料。")
    elif failed:
        st.sidebar.caption("本次操作失敗，可查看保存紀錄或重新輸入。")
    elif not has_engineering:
        st.sidebar.caption("先完成工程分析，才可進入 AI 查核；目前收件紀錄仍可匯出。")
    return previous

from triage.labels import LabelPlan, merge, plan_impact, plan_needs_info, plan_type


def test_plan_type_swaps_wrong_type_label():
    plan = plan_type({"blocklist", "impact: low"}, "whitelist", "reporter wants it unblocked")
    assert plan.add == {"whitelist"} and plan.remove == {"blocklist"}


def test_plan_type_ignores_unknown_or_current_type():
    assert plan_type({"blocklist"}, "blocklist", "").empty
    assert plan_type({"blocklist"}, "declined", "").empty


def test_plan_impact_replaces_previous_impact():
    plan = plan_impact({"impact: low"}, "high", "top 1k site")
    assert plan.add == {"impact: high"} and plan.remove == {"impact: low"}
    assert plan_impact({"impact: high"}, "high", "").empty
    assert plan_impact(set(), "urgent", "").empty


def test_needs_info_only_on_that_recommendation():
    assert plan_needs_info(set(), "needs_info").add == {"needs info"}
    assert plan_needs_info(set(), "block").empty


def test_merge_never_removes_what_it_adds():
    merged = merge(LabelPlan(add={"a"}), LabelPlan(remove={"a", "b"}))
    assert merged.add == {"a"} and merged.remove == {"b"}

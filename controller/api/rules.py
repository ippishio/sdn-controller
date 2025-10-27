import logging
from fastapi import APIRouter, HTTPException


from controller.db.models import BalanceRule
from controller.db import db
from controller.api.controller_adapter import controller


logger = logging.getLogger(__name__)

router = APIRouter(prefix="/rules")


@router.post("/")
async def create_rule(rule: BalanceRule):
    logger.debug(f"creating rule with id {rule.uid}")
    controller.apply_balancing_rule(rule)
    rule.save(db)
    return rule


@router.delete("/{_id}")
async def delete_rule(rule_id: str):
    logger.debug(f"deleting rule with id {rule_id}")
    rule = BalanceRule.get_by_id(rule_id)
    controller.delete_balancing_rule(rule)
    rule = BalanceRule.delete_by_id(rule_id, db)
    if rule is None:
        raise HTTPException(404, "Rule not found")
    return rule_id


@router.get("/")
async def get_all_rules():
    logger.debug("getting all rules")
    return BalanceRule.get_all(db)


@router.put("/{_id}")
async def update_rule(rule_id: str, new_rule: BalanceRule):
    # not working
    return
    logger.debug(f"updating rule with id {rule_id}, new_data: {str(new_rule)}")
    old_rule = BalanceRule.get_by_id(rule_id)
    if old_rule is None:
        raise HTTPException(404, "Rule not found")
    for attr in ["protocol", "port", "virtual_ip", "backend_ip", "algorithm"]:
        setattr(old_rule, attr, getattr(new_rule, attr))
    old_rule.save(db)
    return old_rule

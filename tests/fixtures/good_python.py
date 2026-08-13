"""
good_python.py — Clean Python fixture.
Expected: zero findings at severity HIGH or above.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List


@dataclass
class InvoiceItem:
    description: str
    quantity: int
    unit_price: float

    def subtotal(self) -> float:
        return self.quantity * self.unit_price


@dataclass
class Invoice:
    customer_name: str
    items: List[InvoiceItem]
    tax_rate: float = 0.1

    def total_before_tax(self) -> float:
        return sum(item.subtotal() for item in self.items)

    def tax_amount(self) -> float:
        return round(self.total_before_tax() * self.tax_rate, 2)

    def grand_total(self) -> float:
        return round(self.total_before_tax() + self.tax_amount(), 2)

    def line_summary(self) -> List[str]:
        return [
            f"{item.description}: {item.quantity} × £{item.unit_price:.2f}"
            f" = £{item.subtotal():.2f}"
            for item in self.items
        ]


def build_sample_invoice() -> Invoice:
    return Invoice(
        customer_name="Acme Corp",
        items=[
            InvoiceItem("Widget A", 10, 2.50),
            InvoiceItem("Widget B", 3, 15.00),
        ],
    )

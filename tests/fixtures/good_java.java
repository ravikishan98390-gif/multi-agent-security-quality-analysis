// good_java.java — Clean Java fixture.
// Expected: zero findings at severity HIGH or above.

import java.util.List;
import java.util.ArrayList;

public class good_java {

    private final String customerName;
    private final List<LineItem> lineItems;
    private final double taxRate;

    public good_java(String customerName, List<LineItem> lineItems, double taxRate) {
        this.customerName = customerName;
        this.lineItems = new ArrayList<>(lineItems);
        this.taxRate = taxRate;
    }

    public double calculateTotalBeforeTax() {
        double total = 0.0;
        for (LineItem item : lineItems) {
            total += item.getSubtotal();
        }
        return total;
    }

    public double calculateTaxAmount() {
        return Math.round(calculateTotalBeforeTax() * taxRate * 100.0) / 100.0;
    }

    public double calculateGrandTotal() {
        return calculateTotalBeforeTax() + calculateTaxAmount();
    }

    public List<String> buildLineSummaries() {
        List<String> summaries = new ArrayList<>();
        for (LineItem item : lineItems) {
            summaries.add(
                String.format("%s: %d x £%.2f = £%.2f",
                    item.getDescription(),
                    item.getQuantity(),
                    item.getUnitPrice(),
                    item.getSubtotal())
            );
        }
        return summaries;
    }

    // --- Inner class ---

    static class LineItem {
        private final String description;
        private final int quantity;
        private final double unitPrice;

        public LineItem(String description, int quantity, double unitPrice) {
            this.description = description;
            this.quantity = quantity;
            this.unitPrice = unitPrice;
        }

        public String getDescription() { return description; }
        public int getQuantity() { return quantity; }
        public double getUnitPrice() { return unitPrice; }

        public double getSubtotal() {
            return quantity * unitPrice;
        }
    }
}

// bad_java.java — Fixture with deliberately planted code-quality issues.
// Issues planted:
//   1. Long method `processAllOrders` (100+ lines) → HIGH long_method
//   2. Poor variable names: `a`, `b`, `temp`, `data` → HIGH/MEDIUM poor_naming
//   3. Deep nesting (depth 5) in `parseOrders` → HIGH deep_nesting
//   4. High cyclomatic complexity in `validateOrder` (CC > 10) → MEDIUM high_complexity
//   5. Duplicate code blocks (same loop body repeated) → HIGH duplicate_code
//   6. Tight coupling: 6+ direct instantiations in one method

import java.util.*;
import java.io.*;
import java.sql.*;
import java.net.*;
import java.math.*;

public class bad_java {

    // Issue #2: poor field names
    private int a;
    private String temp;
    private Object data;

    /**
     * Issue #1: god method — 100+ lines.
     * Issue #6: tight coupling — 7 direct instantiations.
     */
    public String processAllOrders(List<Map<String, Object>> orders) {
        StringBuilder sb = new StringBuilder();
        ArrayList<String> processed = new ArrayList<>();
        HashMap<String, Integer> counts = new HashMap<>();
        LinkedList<String> queue = new LinkedList<>();
        TreeMap<String, String> sorted = new TreeMap<>();
        HashSet<String> seen = new HashSet<>();
        PriorityQueue<String> pq = new PriorityQueue<>();   // 7 instantiations

        // --- Duplicate block A ---
        for (Map<String, Object> order : orders) {
            if (order == null) continue;
            String id = (String) order.get("id");
            if (id != null && !id.isEmpty()) {
                processed.add(id.toUpperCase());
                counts.put(id, counts.getOrDefault(id, 0) + 1);
            } else {
                processed.add("UNKNOWN");
            }
        }

        // Padding lines to push method over 40 lines -------------------------
        int step1 = processed.size();
        int step2 = step1 * 2;
        int step3 = step2 + 1;
        int step4 = step3 - 1;
        double step5 = (double) step4 / Math.max(step1, 1);
        double step6 = Math.pow(step5, 2);
        double step7 = Math.abs(step6);
        double step8 = Math.round(step7 * 100.0) / 100.0;
        String step9 = String.valueOf(step8);
        byte[] step10 = step9.getBytes();
        String step11 = Base64.getEncoder().encodeToString(step10);
        String step12 = step11.replace("=", "");
        String step13 = step12.length() > 16 ? step12.substring(0, 16) : step12;
        String step14 = step13.toUpperCase();
        int step15 = step14.hashCode();
        int step16 = Math.abs(step15) % 100;
        double step17 = (double) step16 / 100.0;
        List<Double> step18 = new ArrayList<>();
        for (int i = 0; i < step1; i++) step18.add(step17);
        double step19 = step18.stream().mapToDouble(Double::doubleValue).sum();
        double step20 = step19 / Math.max(step18.size(), 1);
        String step21 = String.format("%.4f", step20);
        String step22 = step21 + "_done";
        int step23 = step22.length();
        long step24 = (long) step23 * step15;
        String step25 = String.valueOf(step24);
        String step26 = String.format("%10s", step25).replace(' ', '0');
        char[] step27 = step26.toCharArray();
        StringBuilder step28sb = new StringBuilder(step26);
        String step29 = step28sb.reverse().toString();
        String step30 = step29.replaceAll("^0+", "");
        if (step30.isEmpty()) step30 = "0";
        long step31 = Long.parseLong(step30);
        long step32 = step31 + step15;
        String step33 = Long.toHexString(step32).toUpperCase();
        String step34 = step33.length() >= 4 ? step33.substring(0, 4) : step33;
        String step35 = step34.toLowerCase() + "_final";

        // --- Duplicate block B (near-copy of block A) ---
        for (Map<String, Object> order : orders) {
            if (order == null) continue;
            String id = (String) order.get("id");
            if (id != null && !id.isEmpty()) {
                queue.add(id.toUpperCase());
                counts.put(id, counts.getOrDefault(id, 0) + 1);
            } else {
                queue.add("UNKNOWN");
            }
        }

        sb.append(step35);
        return sb.toString();
    }

    /**
     * Issue #3: deep nesting — depth 5.
     */
    public List<String> parseOrders(List<Map<String, Object>> records) {
        List<String> output = new ArrayList<>();
        for (Map<String, Object> record : records) {           // depth 1
            if (Boolean.TRUE.equals(record.get("active"))) {  // depth 2
                Object fieldsObj = record.get("fields");
                if (fieldsObj instanceof List) {
                    List<?> fields = (List<?>) fieldsObj;
                    for (Object fieldObj : fields) {           // depth 3
                        if (fieldObj instanceof Map) {
                            Map<?, ?> field = (Map<?, ?>) fieldObj;
                            if (Boolean.TRUE.equals(field.get("required"))) { // depth 4
                                Object values = field.get("values");
                                if (values instanceof List) {
                                    for (Object v : (List<?>) values) {       // depth 5
                                        if (v != null) {
                                            output.add(v.toString());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        return output;
    }

    /**
     * Issue #4: cyclomatic complexity > 10.
     * Issue #2: poor parameter names `b`, `temp`.
     */
    public boolean validateOrder(Object b, String temp, String role,
                                  String env, boolean flag,
                                  String region, String plan) {
        if (b == null) return false;
        if (!(b instanceof String)) return false;
        if (role.equals("admin")) {
            if (env.equals("prod")) {
                if (flag) {
                    if (region.equals("us-east")) {
                        if (plan.equals("enterprise")) return true;
                        else if (plan.equals("pro")) return true;
                        else return false;
                    } else if (region.equals("eu-west")) {
                        return true;
                    } else {
                        return false;
                    }
                } else {
                    return false;
                }
            } else if (env.equals("staging")) {
                return true;
            } else {
                return false;
            }
        } else if (role.equals("user")) {
            return b instanceof String && !((String) b).isEmpty();
        }
        return false;
    }
}

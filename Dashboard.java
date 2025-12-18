import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.sql.*;
import java.util.ArrayList;
import java.util.List;
import javax.swing.Timer;

public class Dashboard extends JFrame {

    private JTable table;
    private DefaultTableModel model;
    private TableRowSorter<DefaultTableModel> sorter;
    private JLabel lblTotal, lblThreats, lblHttps, lblHttp;

    private TrafficGraphPanel lineGraphPanel;
    private PieChartPanel pieChartPanel;

    private JTextField txtSearch;
    private JComboBox<String> cmbFilter;

    private static final String DB_URL = "jdbc:sqlite:sentinal.db";

    private int lastId = 0;

    public Dashboard() {
        setTitle("Sentinal - Cyber Defense & Analytics Platform (v6.0)");
        setSize(1300, 950);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);
        setLayout(new BorderLayout());

        JPanel topContainer = new JPanel(new BorderLayout());
        topContainer.setBackground(new Color(20, 25, 30));

        JPanel statsPanel = new JPanel(new GridLayout(1, 4));
        statsPanel.setPreferredSize(new Dimension(1200, 80));
        statsPanel.setBackground(new Color(20, 25, 30));

        lblTotal = createStatLabel("TOPLAM TRAFIK", Color.WHITE);
        lblThreats = createStatLabel("AKTIF TEHDIT", new Color(255, 50, 50));
        lblHttps = createStatLabel("HTTPS (GUVENLI)", new Color(50, 255, 100));
        lblHttp = createStatLabel("HTTP (ACIK)", new Color(255, 180, 50));

        statsPanel.add(lblTotal); statsPanel.add(lblThreats); statsPanel.add(lblHttps); statsPanel.add(lblHttp);

        JPanel filterPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 15, 10));
        filterPanel.setBackground(new Color(40, 45, 50));
        filterPanel.setBorder(new EmptyBorder(5, 10, 5, 10));

        JLabel lblSearch = new JLabel("🔍 Hizli Arama:");
        lblSearch.setForeground(Color.WHITE);
        lblSearch.setFont(new Font("Segoe UI", Font.BOLD, 14));

        txtSearch = new JTextField(20);
        txtSearch.setFont(new Font("Segoe UI", Font.PLAIN, 14));
        txtSearch.addKeyListener(new KeyAdapter() {
            @Override
            public void keyReleased(KeyEvent e) {
                filterData();
            }
        });

        JLabel lblFilter = new JLabel("⚡ Kategori:");
        lblFilter.setForeground(Color.WHITE);
        lblFilter.setFont(new Font("Segoe UI", Font.BOLD, 14));

        String[] filters = {"Tumu", "Sadece Tehditler", "Sadece HTTPS", "Sadece HTTP", "Turkiye Trafigi"};
        cmbFilter = new JComboBox<>(filters);
        cmbFilter.setFont(new Font("Segoe UI", Font.PLAIN, 14));
        cmbFilter.addActionListener(e -> filterData());

        filterPanel.add(lblSearch);
        filterPanel.add(txtSearch);
        filterPanel.add(Box.createHorizontalStrut(20));
        filterPanel.add(lblFilter);
        filterPanel.add(cmbFilter);

        topContainer.add(statsPanel, BorderLayout.NORTH);
        topContainer.add(filterPanel, BorderLayout.SOUTH);
        add(topContainer, BorderLayout.NORTH);

        String[] columns = {"ID", "Zaman", "Kaynak IP", "Port", "Hedef IP", "ULKE", "Servis", "Boyut"};
        model = new DefaultTableModel(columns, 0);

        sorter = new TableRowSorter<>(model);

        table = new JTable(model);
        table.setRowSorter(sorter);
        table.setRowHeight(28);
        table.setFont(new Font("Consolas", Font.PLAIN, 13));
        table.setShowGrid(false);
        table.setIntercellSpacing(new Dimension(0, 0));

        table.getTableHeader().setFont(new Font("Segoe UI", Font.BOLD, 14));
        table.getTableHeader().setBackground(new Color(45, 45, 55));
        table.getTableHeader().setForeground(Color.WHITE);

        table.getColumnModel().getColumn(0).setPreferredWidth(50);
        table.getColumnModel().getColumn(5).setPreferredWidth(100);
        table.getColumnModel().getColumn(6).setPreferredWidth(150);

        table.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

                int modelRow = table.convertRowIndexToModel(row);

                String service = (String) model.getValueAt(modelRow, 6);
                String country = (String) model.getValueAt(modelRow, 5);

                if (!isSelected) c.setBackground(row % 2 == 0 ? Color.WHITE : new Color(245, 245, 250));
                c.setForeground(Color.BLACK);

                if (service != null) {
                    if (service.contains("TEHLIKE")) {
                        c.setBackground(new Color(255, 220, 220));
                        c.setForeground(Color.RED);
                        c.setFont(c.getFont().deriveFont(Font.BOLD));
                    } else if (service.contains("HTTPS")) {
                        c.setForeground(new Color(0, 100, 0));
                    }
                }

                if (column == 5 && country != null) {
                    if (country.contains("TR")) {
                        c.setForeground(new Color(200, 0, 0));
                        c.setFont(c.getFont().deriveFont(Font.BOLD));
                    } else if (country.contains("USA")) c.setForeground(Color.BLUE);
                }

                if (isSelected) {
                    c.setBackground(new Color(180, 220, 255));
                    c.setForeground(Color.BLACK);
                }
                return c;
            }
        });

        add(new JScrollPane(table), BorderLayout.CENTER);

        JPanel bottomPanel = new JPanel(new GridLayout(1, 2));
        bottomPanel.setPreferredSize(new Dimension(1200, 200));

        lineGraphPanel = new TrafficGraphPanel();
        pieChartPanel = new PieChartPanel();

        bottomPanel.add(lineGraphPanel);
        bottomPanel.add(pieChartPanel);

        add(bottomPanel, BorderLayout.SOUTH);

        Timer timer = new Timer(1000, e -> readDB());
        timer.start();
    }

    private void filterData() {
        String text = txtSearch.getText();
        String category = (String) cmbFilter.getSelectedItem();

        List<RowFilter<Object, Object>> filters = new ArrayList<>();

        if (text.trim().length() > 0) {
            filters.add(RowFilter.regexFilter("(?i)" + text));
        }

        if (category != null && !category.equals("Tumu")) {
            if (category.equals("Sadece Tehditler")) {
                filters.add(RowFilter.regexFilter("TEHLIKE", 6)); // 6. Sütun (Servis)
            } else if (category.equals("Sadece HTTPS")) {
                filters.add(RowFilter.regexFilter("HTTPS", 6));
            } else if (category.equals("Sadece HTTP")) {
                filters.add(RowFilter.regexFilter("HTTP", 6));
            } else if (category.equals("Turkiye Trafigi")) {
                filters.add(RowFilter.regexFilter("TR", 5)); // 5. Sütun (Ülke)
            }
        }

        if (filters.isEmpty()) {
            sorter.setRowFilter(null);
        } else {
            sorter.setRowFilter(RowFilter.andFilter(filters));
        }
    }

    private JLabel createStatLabel(String title, Color color) {
        JLabel lbl = new JLabel("<html><center>" + title + "<br><font size=6>0</font></center></html>", SwingConstants.CENTER);
        lbl.setForeground(color);
        lbl.setFont(new Font("Segoe UI", Font.BOLD, 15));
        lbl.setOpaque(true); lbl.setBackground(new Color(35, 35, 45));
        lbl.setBorder(BorderFactory.createMatteBorder(0, 0, 0, 1, Color.GRAY));
        return lbl;
    }

    private void updateStatLabel(JLabel lbl, String title, int count) {
        lbl.setText("<html><center>" + title + "<br><font size=6>" + count + "</font></center></html>");
    }

    private void readDB() {
        String sql = "SELECT * FROM logs WHERE id > " + lastId;

        try (Connection conn = DriverManager.getConnection(DB_URL);
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {

            int newPacketsCount = 0;
            boolean threatDetected = false;

            while (rs.next()) {
                int id = rs.getInt("id");
                String time = rs.getString("time");
                String srcIp = rs.getString("src_ip");
                int srcPort = rs.getInt("src_port");
                String dstIp = rs.getString("dst_ip");
                String country = rs.getString("country");
                int dstPort = rs.getInt("dst_port");
                String service = rs.getString("service");
                int size = rs.getInt("size");
                int isThreat = rs.getInt("is_threat");

                if (isThreat == 1) threatDetected = true;

                model.addRow(new Object[]{id, time, srcIp, srcPort, dstIp, country, service, size});
                lastId = id;
                newPacketsCount++;
            }

            if (threatDetected) Toolkit.getDefaultToolkit().beep();

            if (newPacketsCount > 0) {

                updateStats();
            }
            lineGraphPanel.addDataPoint(newPacketsCount);

        } catch (SQLException e) {
            System.out.println("DB Baglanti Hatasi: " + e.getMessage());
        }
    }

    private void updateStats() {
        int total = model.getRowCount();
        int threats = 0, https = 0, http = 0;
        for (int i = 0; i < total; i++) {
            String srv = (String) model.getValueAt(i, 6);
            if (srv.contains("TEHLIKE")) threats++;
            if (srv.contains("HTTPS")) https++;
            else if (srv.contains("HTTP")) http++;
        }
        updateStatLabel(lblTotal, "TOPLAM TRAFIK", total);
        updateStatLabel(lblThreats, "AKTIF TEHDIT", threats);
        updateStatLabel(lblHttps, "HTTPS (GUVENLI)", https);
        updateStatLabel(lblHttp, "HTTP (ACIK)", http);
        pieChartPanel.updateData(https, http, threats);
    }

    public static void main(String[] args) {
        try { UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName()); } catch (Exception ignored) {}
        SwingUtilities.invokeLater(() -> new Dashboard().setVisible(true));
    }

    class TrafficGraphPanel extends JPanel {
        private List<Integer> dataPoints = new ArrayList<>();
        private final int MAX_DATA_POINTS = 60;
        public TrafficGraphPanel() {
            setBackground(new Color(30, 30, 35));
            for (int i = 0; i < MAX_DATA_POINTS; i++) dataPoints.add(0);
        }
        public void addDataPoint(int packetCount) {
            dataPoints.add(packetCount);
            if (dataPoints.size() > MAX_DATA_POINTS) dataPoints.remove(0);
            repaint();
        }
        @Override
        protected void paintComponent(Graphics g) {
            super.paintComponent(g);
            Graphics2D g2 = (Graphics2D) g;
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            int width = getWidth(), height = getHeight(), padding = 25;
            g2.setColor(Color.WHITE);
            g2.drawString("CANLI TRAFIK HIZI (Paket/Sn)", 15, 20);
            g2.setColor(new Color(0, 200, 255));
            g2.setStroke(new BasicStroke(2f));
            int maxVal = 10;
            for (int val : dataPoints) maxVal = Math.max(maxVal, val);
            int xStep = width / (MAX_DATA_POINTS - 1);
            for (int i = 0; i < dataPoints.size() - 1; i++) {
                int y1 = height - padding - (int) ((double) dataPoints.get(i) / maxVal * (height - 2 * padding));
                int y2 = height - padding - (int) ((double) dataPoints.get(i + 1) / maxVal * (height - 2 * padding));
                g2.drawLine(i * xStep, y1, (i + 1) * xStep, y2);
            }
        }
    }

    class PieChartPanel extends JPanel {
        private int https = 0, http = 0, threats = 0;
        public PieChartPanel() { setBackground(new Color(30, 30, 35)); }
        public void updateData(int https, int http, int threats) {
            this.https = https; this.http = http; this.threats = threats; repaint();
        }
        @Override
        protected void paintComponent(Graphics g) {
            super.paintComponent(g);
            Graphics2D g2 = (Graphics2D) g;
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            int width = getWidth(), height = getHeight();
            int total = https + http + threats;
            g2.setColor(Color.WHITE); g2.drawString("TRAFIK DAGILIMI", 15, 20);
            if (total == 0) return;
            int angleHttps = (int) (360.0 * https / total);
            int angleThreats = (int) (360.0 * threats / total);
            int angleHttp = 360 - angleHttps - angleThreats;
            int diameter = Math.min(width, height) - 60;
            int x = (width - diameter) / 2;
            int y = (height - diameter) / 2 + 10;
            g2.setColor(new Color(50, 200, 100)); g2.fillArc(x, y, diameter, diameter, 0, angleHttps);
            g2.setColor(new Color(255, 180, 50)); g2.fillArc(x, y, diameter, diameter, angleHttps, angleHttp);
            g2.setColor(new Color(255, 50, 50)); g2.fillArc(x, y, diameter, diameter, angleHttps + angleHttp, angleThreats);
            g2.setColor(getBackground()); g2.fillOval(x + diameter/4, y + diameter/4, diameter/2, diameter/2);
            g2.setColor(Color.WHITE); g2.setFont(new Font("Segoe UI", Font.PLAIN, 12));
            g2.drawString("■ HTTPS: " + https, width - 100, 40);
            g2.drawString("■ HTTP: " + http, width - 100, 60);
            g2.drawString("■ TEHDIT: " + threats, width - 100, 80);
        }
    }
}
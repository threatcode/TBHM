import type { Meta, StoryObj } from "@storybook/react";
import HeatMap from "../visualization/HeatMap";

const meta = {
  title: "Visualization/HeatMap",
  component: HeatMap,
  parameters: {
    layout: "padded",
  },
  tags: ["autodocs"],
} satisfies Meta<typeof HeatMap>;

export default meta;
type Story = StoryObj<typeof meta>;

export const Default: Story = {
  args: {
    data: {
      total_vulns: 15,
      risk_score: 6.5,
      by_severity: {
        critical: 2,
        high: 5,
        medium: 6,
        low: 2,
        info: 0,
      },
      by_category: {
        "SQL Injection": 3,
        "XSS": 4,
        "CSRF": 2,
        "Auth": 3,
        "Config": 2,
        "Info": 1,
      },
      high_risk_areas: [
        { name: "Login Endpoint", severity: "critical", url: "https://api.example.com/login" },
        { name: "Admin Panel", severity: "high", url: "https://admin.example.com" },
      ],
    },
  },
};
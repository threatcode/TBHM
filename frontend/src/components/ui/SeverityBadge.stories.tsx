import type { Meta, StoryObj } from "@storybook/react";
import SeverityBadge from "../ui/SeverityBadge";

const meta = {
  title: "UI/SeverityBadge",
  component: SeverityBadge,
  parameters: {
    layout: "centered",
  },
  tags: ["autodocs"],
} satisfies Meta<typeof SeverityBadge>;

export default meta;
type Story = StoryObj<typeof meta>;

export const Critical: Story = {
  args: {
    severity: "critical",
  },
};

export const High: Story = {
  args: {
    severity: "high",
  },
};

export const Medium: Story = {
  args: {
    severity: "medium",
  },
};

export const Low: Story = {
  args: {
    severity: "low",
  },
};

export const Info: Story = {
  args: {
    severity: "info",
  },
};
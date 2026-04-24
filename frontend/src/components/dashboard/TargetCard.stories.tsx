import type { Meta, StoryObj } from "@storybook/react";
import TargetCard from "../dashboard/TargetCard";

const meta = {
  title: "Dashboard/TargetCard",
  component: TargetCard,
  parameters: {
    layout: "centered",
  },
  tags: ["autodocs"],
} satisfies Meta<typeof TargetCard>;

export default meta;
type Story = StoryObj<typeof meta>;

export const Default: Story = {
  args: {
    target: {
      id: "123",
      name: "Acme Corp",
      domain: "acme.com",
      company: "Acme Inc.",
      created_at: "2024-01-15T10:00:00Z",
      updated_at: "2024-01-15T10:00:00Z",
    },
  },
};

export const WithDescription: Story = {
  args: {
    target: {
      id: "123",
      name: "Acme Corp",
      domain: "acme.com",
      description: "Main e-commerce platform",
      company: "Acme Inc.",
      created_at: "2024-01-15T10:00:00Z",
      updated_at: "2024-01-15T10:00:00Z",
    },
  },
};
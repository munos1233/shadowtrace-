/** ApprovalActionModal — approve / reject dialog (ISSUE-073). */

import { Modal, Form, Input } from "antd";

const { TextArea } = Input;

interface ApprovalActionModalProps {
  open: boolean;
  actionId: string | null;
  mode: "approve" | "reject";
  loading: boolean;
  onConfirm: (actionId: string, comment?: string) => void;
  onCancel: () => void;
}

export default function ApprovalActionModal({
  open,
  actionId,
  mode,
  loading,
  onConfirm,
  onCancel,
}: ApprovalActionModalProps) {
  const [form] = Form.useForm<{ comment: string }>();

  const title = mode === "approve" ? "批准动作" : "拒绝动作";
  const okText = mode === "approve" ? "批准" : "拒绝";
  const isReject = mode === "reject";

  const handleOk = async () => {
    if (!actionId) return;
    const values = await form.validateFields();
    onConfirm(actionId, isReject ? values.comment : undefined);
    form.resetFields();
  };

  return (
    <Modal
      title={title}
      open={open}
      onOk={handleOk}
      onCancel={() => {
        form.resetFields();
        onCancel();
      }}
      confirmLoading={loading}
      okText={okText}
      okButtonProps={{ danger: isReject }}
      cancelText="取消"
      destroyOnHidden
    >
      <Form form={form} layout="vertical">
        {isReject && (
          <Form.Item
            name="comment"
            label="拒绝原因"
            rules={[{ required: true, message: "拒绝必须填写原因" }]}
          >
            <TextArea rows={3} placeholder="请填写拒绝原因" />
          </Form.Item>
        )}
        {!isReject && (
          <Form.Item name="comment" label="审批备注（可选）">
            <TextArea rows={2} placeholder="可选备注" />
          </Form.Item>
        )}
      </Form>
    </Modal>
  );
}

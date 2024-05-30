// This file is automatically generated, so please do not edit it.
// Generated by `flutter_rust_bridge`@ 2.0.0-dev.36.

// ignore_for_file: invalid_use_of_internal_member, unused_import, unnecessary_import

import 'frb_generated.dart';
import 'package:flutter_rust_bridge/flutter_rust_bridge_for_generated.dart';
import 'package:freezed_annotation/freezed_annotation.dart' hide protected;
part 'model.freezed.dart';

class BackupRequest {
  /// Path to the backup.
  ///
  /// If not set, it defaults to `backup.sql` for mainnet and `backup-testnet.sql` for testnet.
  /// The file will be saved in [ConnectRequest]'s `data_dir`.
  final String? backupPath;

  const BackupRequest({
    this.backupPath,
  });

  @override
  int get hashCode => backupPath.hashCode;

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is BackupRequest && runtimeType == other.runtimeType && backupPath == other.backupPath;
}

class ConnectRequest {
  final String mnemonic;
  final String? dataDir;
  final Network network;

  const ConnectRequest({
    required this.mnemonic,
    this.dataDir,
    required this.network,
  });

  @override
  int get hashCode => mnemonic.hashCode ^ dataDir.hashCode ^ network.hashCode;

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is ConnectRequest &&
          runtimeType == other.runtimeType &&
          mnemonic == other.mnemonic &&
          dataDir == other.dataDir &&
          network == other.network;
}

class GetInfoRequest {
  final bool withScan;

  const GetInfoRequest({
    required this.withScan,
  });

  @override
  int get hashCode => withScan.hashCode;

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is GetInfoRequest && runtimeType == other.runtimeType && withScan == other.withScan;
}

class GetInfoResponse {
  /// Usable balance. This is the confirmed onchain balance minus `pending_send_sat`.
  final BigInt balanceSat;

  /// Amount that is being used for ongoing Send swaps
  final BigInt pendingSendSat;

  /// Incoming amount that is pending from ongoing Receive swaps
  final BigInt pendingReceiveSat;
  final String pubkey;

  const GetInfoResponse({
    required this.balanceSat,
    required this.pendingSendSat,
    required this.pendingReceiveSat,
    required this.pubkey,
  });

  @override
  int get hashCode =>
      balanceSat.hashCode ^ pendingSendSat.hashCode ^ pendingReceiveSat.hashCode ^ pubkey.hashCode;

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is GetInfoResponse &&
          runtimeType == other.runtimeType &&
          balanceSat == other.balanceSat &&
          pendingSendSat == other.pendingSendSat &&
          pendingReceiveSat == other.pendingReceiveSat &&
          pubkey == other.pubkey;
}

@freezed
sealed class LiquidSdkEvent with _$LiquidSdkEvent {
  const LiquidSdkEvent._();

  const factory LiquidSdkEvent.paymentFailed({
    required Payment details,
  }) = LiquidSdkEvent_PaymentFailed;
  const factory LiquidSdkEvent.paymentPending({
    required Payment details,
  }) = LiquidSdkEvent_PaymentPending;
  const factory LiquidSdkEvent.paymentRefunded({
    required Payment details,
  }) = LiquidSdkEvent_PaymentRefunded;
  const factory LiquidSdkEvent.paymentRefundPending({
    required Payment details,
  }) = LiquidSdkEvent_PaymentRefundPending;
  const factory LiquidSdkEvent.paymentSucceed({
    required Payment details,
  }) = LiquidSdkEvent_PaymentSucceed;
  const factory LiquidSdkEvent.paymentWaitingConfirmation({
    required Payment details,
  }) = LiquidSdkEvent_PaymentWaitingConfirmation;
  const factory LiquidSdkEvent.synced() = LiquidSdkEvent_Synced;
}

enum Network {
  liquid,
  liquidTestnet,
  ;
}

/// Represents an SDK payment.
///
/// By default, this is an onchain tx. It may represent a swap, if swap metadata is available.
class Payment {
  /// The tx ID of the onchain transaction
  final String txId;

  /// The swap ID, if any swap is associated with this payment
  final String? swapId;

  /// Composite timestamp that can be used for sorting or displaying the payment.
  ///
  /// If this payment has an associated swap, it is the swap creation time. Otherwise, the point
  /// in time when the underlying tx was included in a block. If there is no associated swap
  /// available and the underlying tx is not yet confirmed, the value is `now()`.
  final int timestamp;

  /// The payment amount, which corresponds to the onchain tx amount.
  ///
  /// In case of an outbound payment (Send), this is the payer amount. Otherwise it's the receiver amount.
  final BigInt amountSat;

  /// If a swap is associated with this payment, this represents the total fees paid by the
  /// sender. In other words, it's the delta between the amount that was sent and the amount
  /// received.
  final BigInt? feesSat;

  /// In case of a Send swap, this is the preimage of the paid invoice (proof of payment).
  final String? preimage;

  /// For a Send swap which was refunded, this is the refund tx id
  final String? refundTxId;

  /// For a Send swap which was refunded, this is the refund amount
  final BigInt? refundTxAmountSat;
  final PaymentType paymentType;

  /// Composite status representing the overall status of the payment.
  ///
  /// If the tx has no associated swap, this reflects the onchain tx status (confirmed or not).
  ///
  /// If the tx has an associated swap, this is determined by the swap status (pending or complete).
  final PaymentState status;

  const Payment({
    required this.txId,
    this.swapId,
    required this.timestamp,
    required this.amountSat,
    this.feesSat,
    this.preimage,
    this.refundTxId,
    this.refundTxAmountSat,
    required this.paymentType,
    required this.status,
  });

  @override
  int get hashCode =>
      txId.hashCode ^
      swapId.hashCode ^
      timestamp.hashCode ^
      amountSat.hashCode ^
      feesSat.hashCode ^
      preimage.hashCode ^
      refundTxId.hashCode ^
      refundTxAmountSat.hashCode ^
      paymentType.hashCode ^
      status.hashCode;

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is Payment &&
          runtimeType == other.runtimeType &&
          txId == other.txId &&
          swapId == other.swapId &&
          timestamp == other.timestamp &&
          amountSat == other.amountSat &&
          feesSat == other.feesSat &&
          preimage == other.preimage &&
          refundTxId == other.refundTxId &&
          refundTxAmountSat == other.refundTxAmountSat &&
          paymentType == other.paymentType &&
          status == other.status;
}

enum PaymentState {
  created,

  /// ## Receive Swaps
  ///
  /// Covers the cases when
  /// - the lockup tx is seen in the mempool or
  /// - our claim tx is broadcast
  ///
  /// When the claim tx is broadcast, `claim_tx_id` is set in the swap.
  ///
  /// ## Send Swaps
  ///
  /// Covers the cases when
  /// - our lockup tx was broadcast or
  /// - a refund was initiated and our refund tx was broadcast
  ///
  /// When the refund tx is broadcast, `refund_tx_id` is set in the swap.
  ///
  /// ## No swap data available
  ///
  /// If no associated swap is found, this indicates the underlying tx is not confirmed yet.
  pending,

  /// ## Receive Swaps
  ///
  /// Covers the case when the claim tx is confirmed.
  ///
  /// ## Send Swaps
  ///
  /// This is the status when the claim tx is broadcast and we see it in the mempool.
  ///
  /// ## No swap data available
  ///
  /// If no associated swap is found, this indicates the underlying tx is confirmed.
  complete,

  /// ## Receive Swaps
  ///
  /// This is the status when the swap failed for any reason and the Receive could not complete.
  ///
  /// ## Send Swaps
  ///
  /// This is the status when a swap refund was initiated and the refund tx is confirmed.
  failed,
  ;
}

enum PaymentType {
  receive,
  send,
  ;
}

class PrepareReceiveRequest {
  final BigInt payerAmountSat;

  const PrepareReceiveRequest({
    required this.payerAmountSat,
  });

  @override
  int get hashCode => payerAmountSat.hashCode;

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is PrepareReceiveRequest &&
          runtimeType == other.runtimeType &&
          payerAmountSat == other.payerAmountSat;
}

class PrepareReceiveResponse {
  final BigInt payerAmountSat;
  final BigInt feesSat;

  const PrepareReceiveResponse({
    required this.payerAmountSat,
    required this.feesSat,
  });

  @override
  int get hashCode => payerAmountSat.hashCode ^ feesSat.hashCode;

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is PrepareReceiveResponse &&
          runtimeType == other.runtimeType &&
          payerAmountSat == other.payerAmountSat &&
          feesSat == other.feesSat;
}

class PrepareSendRequest {
  final String invoice;

  const PrepareSendRequest({
    required this.invoice,
  });

  @override
  int get hashCode => invoice.hashCode;

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is PrepareSendRequest && runtimeType == other.runtimeType && invoice == other.invoice;
}

class PrepareSendResponse {
  final String invoice;
  final BigInt feesSat;

  const PrepareSendResponse({
    required this.invoice,
    required this.feesSat,
  });

  @override
  int get hashCode => invoice.hashCode ^ feesSat.hashCode;

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is PrepareSendResponse &&
          runtimeType == other.runtimeType &&
          invoice == other.invoice &&
          feesSat == other.feesSat;
}

class ReceivePaymentResponse {
  final String id;
  final String invoice;

  const ReceivePaymentResponse({
    required this.id,
    required this.invoice,
  });

  @override
  int get hashCode => id.hashCode ^ invoice.hashCode;

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is ReceivePaymentResponse &&
          runtimeType == other.runtimeType &&
          id == other.id &&
          invoice == other.invoice;
}

class RestoreRequest {
  final String? backupPath;

  const RestoreRequest({
    this.backupPath,
  });

  @override
  int get hashCode => backupPath.hashCode;

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is RestoreRequest && runtimeType == other.runtimeType && backupPath == other.backupPath;
}

class SendPaymentResponse {
  final Payment payment;

  const SendPaymentResponse({
    required this.payment,
  });

  @override
  int get hashCode => payment.hashCode;

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is SendPaymentResponse && runtimeType == other.runtimeType && payment == other.payment;
}

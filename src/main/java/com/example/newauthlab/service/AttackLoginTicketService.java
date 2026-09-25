package com.example.newauthlab.service;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.stereotype.Service;

@Service
public class AttackLoginTicketService {

	/*
	 * attacksimulatorからの
	 * 実ログイン引き継ぎ用一時チケット
	 */
	private final Map<String, TicketData> tickets =
			new ConcurrentHashMap<>();

	/*
	 * チケットの有効時間
	 * 2分
	 */
	private static final long TICKET_VALID_SECONDS = 120;

	/**
	 * 認証済みユーザーから
	 * 一時ログインチケットを作成する
	 *
	 * @param username 認証済みユーザー名
	 * @return 一時チケット
	 */
	public String createTicket(
			String username) {

		if (username == null
				|| username.isBlank()) {

			throw new IllegalArgumentException(
					"ユーザー名が指定されていません。");
		}

		String ticket =
				UUID.randomUUID().toString();

		Instant expiresAt =
				Instant.now().plusSeconds(
						TICKET_VALID_SECONDS);

		tickets.put(
				ticket,
				new TicketData(
						username,
						expiresAt));

		return ticket;
	}

	/**
	 * チケットを使用して
	 * ユーザー名を取得する
	 *
	 * 使用後はチケットを削除するため、
	 * 1回だけ利用可能
	 *
	 * @param ticket 一時チケット
	 * @return ユーザー名
	 */
	public String consumeTicket(
			String ticket) {

		if (ticket == null
				|| ticket.isBlank()) {

			return null;
		}

		TicketData ticketData =
				tickets.remove(ticket);

		if (ticketData == null) {

			return null;
		}

		/*
		 * 有効期限切れ
		 */
		if (ticketData.expiresAt()
				.isBefore(Instant.now())) {

			return null;
		}

		return ticketData.username();
	}

	/**
	 * 一時チケット情報
	 */
	private record TicketData(
			String username,
			Instant expiresAt) {
	}
}
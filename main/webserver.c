#include "stdint.h"
#include "stdio.h"
#include "lwip/sockets.h"
#include "targeting.h"
#include <string.h>

char header[] = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: ";

int setup_socket()
{
	int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);

	struct timeval timeout;
	timeout.tv_sec = 100;
	timeout.tv_usec = 0;
	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

	struct sockaddr_in sock_addr;
	sock_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	sock_addr.sin_family = AF_INET;
	sock_addr.sin_port = htons(CONFIG_HTTP_PORT);
	sock_addr.sin_len = 16;

	int res = bind(sock, (struct sockaddr *)&sock_addr, sizeof(sock_addr));
	if(res < 0)
	{
		printf("Couldn't bind socket err: %d\n",res);
		esp_restart();
	}

	listen(sock, 0);

	return sock;
}

void web_server_start_loop() {
	uint8_t* recv_buffer;
	int recv_buffer_size = 20;
	recv_buffer = malloc(recv_buffer_size);

	int header_length = strlen(header);

	int listen_sock_fd = setup_socket();

	while (1) {
		int sock = accept(listen_sock_fd, NULL, NULL);
		recv(sock, recv_buffer, recv_buffer_size, 0);

		if(strncmp("GET", (char*)recv_buffer, 3) == 0) {
			int response_length = get_cracked_hashes_len();

			char content_lenght[32];
			snprintf(content_lenght, 16, "%d\r\n\r\n", response_length-1); 
			int l_content_length = strlen(content_lenght);

			char* response = malloc(response_length+header_length+ l_content_length);
			get_cracked_hashes(response+header_length+l_content_length, response_length);
			memcpy(response, header, header_length);
			memcpy(response+header_length, content_lenght, l_content_length);

			int wrote = write(sock, response, response_length+header_length+l_content_length);
			printf("%d\n", wrote);

			free(response);
		} 
		shutdown(sock, 2);
		close(sock);

	}
}

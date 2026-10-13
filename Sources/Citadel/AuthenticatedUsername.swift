import NIO
import NIOSSH

/// Wraps a server's user authentication delegate for one connection, and records the username the connection
/// authenticated as.
///
/// Apple's NIOSSH tells only the user authentication delegate which request succeeded. It accepts channels and
/// global requests only once user authentication has succeeded, so those read ``username`` after it is set.
final class UsernameRecordingAuthenticationDelegate: NIOSSHServerUserAuthenticationDelegate {
    private let base: NIOSSHServerUserAuthenticationDelegate
    private let recordedUsername: NIOLoopBoundBox<String?>

    /// The username of the request that succeeded, or `nil` until one has. Read it on the connection's event loop.
    var username: String? {
        recordedUsername.value
    }

    init(base: NIOSSHServerUserAuthenticationDelegate, eventLoop: EventLoop) {
        self.base = base
        self.recordedUsername = .makeEmptyBox(valueType: String.self, eventLoop: eventLoop)
    }

    var supportedAuthenticationMethods: NIOSSHAvailableUserAuthenticationMethods {
        base.supportedAuthenticationMethods
    }

    func requestReceived(
        request: NIOSSHUserAuthenticationRequest,
        responsePromise: EventLoopPromise<NIOSSHUserAuthenticationOutcome>
    ) {
        let username = request.username
        let outcome = responsePromise.futureResult.eventLoop.makePromise(of: NIOSSHUserAuthenticationOutcome.self)
        outcome.futureResult.whenSuccess { [recordedUsername] result in
            if case .success = result {
                recordedUsername.value = username
            }
        }
        outcome.futureResult.cascade(to: responsePromise)
        base.requestReceived(request: request, responsePromise: outcome)
    }
}

/// Hands one connection's global requests to the server's delegate, with the username the connection
/// authenticated as.
struct AuthenticatedGlobalRequestDelegate: GlobalRequestDelegate {
    let server: CitadelServerDelegate
    let authentication: UsernameRecordingAuthenticationDelegate

    func tcpForwardingRequest(
        _ request: GlobalRequest.TCPForwardingRequest,
        handler: NIOSSHHandler,
        promise: EventLoopPromise<GlobalRequest.TCPForwardingResponse>
    ) {
        server.tcpForwardingRequest(request, handler: handler, username: authentication.username, promise: promise)
    }
}

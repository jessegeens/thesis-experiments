export async function fetchResource(target, session) {
    const response = await (
        await session.fetch(target, {})
    ).text();
    return response;
}
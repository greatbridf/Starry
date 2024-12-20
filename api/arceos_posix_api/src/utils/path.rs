use axerrno::LinuxResult;

pub struct Path<'lt> {
    all: &'lt str,
}

pub struct PathIterator<'lt> {
    rem: &'lt str,
}

impl<'lt> Path<'lt> {
    pub fn new(all: &'lt str) -> LinuxResult<Self> {
        if all.is_empty() {
            Err(axerrno::LinuxError::ENOENT)
        } else {
            Ok(Self { all })
        }
    }

    pub fn is_absolute(&self) -> bool {
        self.all.starts_with('/')
    }

    pub fn iter(&self) -> PathIterator<'lt> {
        PathIterator::new(self.all)
    }
}

impl<'lt> PathIterator<'lt> {
    fn new(all: &'lt str) -> Self {
        Self { rem: all }
    }
}

#[derive(Debug)]
pub enum PathComponent<'lt> {
    Name(&'lt str),
    TrailingEmpty,
    Current,
    Parent,
}

impl<'lt> Iterator for PathIterator<'lt> {
    type Item = PathComponent<'lt>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.rem.is_empty() {
            return None;
        }

        let trimmed = self.rem.trim_start_matches('/');

        let next_start = trimmed.find('/').unwrap_or(trimmed.len());
        let (cur, rem) = trimmed.split_at(next_start);

        self.rem = rem;

        match cur {
            "" => Some(PathComponent::TrailingEmpty),
            "." => Some(PathComponent::Current),
            ".." => Some(PathComponent::Parent),
            cur => Some(PathComponent::Name(cur)),
        }
    }
}

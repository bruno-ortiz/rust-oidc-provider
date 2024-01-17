use crate::configuration::OpenIDProviderConfiguration;
use crate::models::client::ClientInformation;
use crate::pairwise::PairwiseError;
use oidc_types::subject::Subject;
use oidc_types::subject_type::SubjectType;

pub fn resolve_sub(
    configuration: &OpenIDProviderConfiguration,
    subject: &Subject,
    client: &ClientInformation,
) -> Result<Subject, PairwiseError> {
    if client.metadata().subject_type == SubjectType::Pairwise {
        let pairwise_resolver = configuration.pairwise_resolver();

        Ok(pairwise_resolver
            .calculate_pairwise_identifier(subject, client)?
            .into_subject())
    } else {
        Ok(subject.clone())
    }
}
